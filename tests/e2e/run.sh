#!/usr/bin/env bash
# End to end: install Access Guard in a real Home Assistant container, upgrade it in place to this
# checkout, and check it as a household would use it (driver.py). Needs docker and git.
#
#   tests/e2e/run.sh [Home Assistant image tag] [from]
#
#   tag   default 2026.10.4; "stable" is the newest release
#   from  "previous" (default): the newest release tag that is not this commit
#         "fresh": no earlier version, this checkout installed directly
#         or any git ref, e.g. v0.2.0
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
TAG=${1:-2026.10.4}
FROM=${2:-previous}
IMAGE=ghcr.io/home-assistant/home-assistant:$TAG
NAME=access-guard-e2e-$$
WORK=$(mktemp -d)
CONFIG=$WORK/config
mkdir -p "$CONFIG/custom_components" "$WORK/old"

in_image() {  # a throwaway shell in the image: the config holds files Home Assistant wrote as root
    docker run --rm --entrypoint sh -v "$CONFIG:/config" -v "$WORK/old:/old:ro" \
        -v "$REPO/custom_components/access_guard:/new:ro" "$IMAGE" -c "$1"
}

finish() {
    status=$?
    if [ $status -ne 0 ] && docker inspect "$NAME" >/dev/null 2>&1; then
        echo "--- Home Assistant log (last 80 lines)"
        docker exec "$NAME" tail -n 80 /config/home-assistant.log || true
    fi
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    in_image "rm -rf /config/* /config/.[!.]*" >/dev/null 2>&1 || true
    rm -rf "$WORK"
    exit $status
}
trap finish EXIT

if [ "$FROM" = previous ]; then
    FROM=fresh
    head=$(git -C "$REPO" rev-parse HEAD)
    for t in $(git -C "$REPO" tag -l 'v*' --sort=-v:refname); do
        if [ "$(git -C "$REPO" rev-list -n 1 "$t")" != "$head" ]; then FROM=$t; break; fi
    done
fi
if [ "$FROM" = fresh ]; then
    cp -r "$REPO/custom_components/access_guard/." "$WORK/old/"
else
    git -C "$REPO" archive "$FROM" custom_components/access_guard | tar -x -C "$WORK/old" --strip-components=2
fi
echo "== Home Assistant $TAG: install $FROM, upgrade to $(git -C "$REPO" describe --tags --always --dirty)"

printf 'default_config:\ncamera:\nlogger:\n  default: warning\n' > "$CONFIG/configuration.yaml"
docker pull -q "$IMAGE" >/dev/null
in_image "cp -r /old /config/custom_components/access_guard"
docker run -d --name "$NAME" -v "$CONFIG:/config" -v "$HERE:/e2e:ro" "$IMAGE" >/dev/null
docker exec "$NAME" python3 /e2e/driver.py install
docker stop -t 60 "$NAME" >/dev/null

echo "== upgrade in place"
in_image 'rm -rf /config/custom_components/access_guard && cp -r /new /config/custom_components/access_guard \
          && rm -rf /config/custom_components/access_guard/__pycache__ \
          && printf "\n203.0.113.9:\n  banned_at: \"2026-10-28T09:00:00+00:00\"\n" > /config/ip_bans.yaml \
          && : > /config/home-assistant.log'
docker start "$NAME" >/dev/null
docker exec "$NAME" python3 /e2e/driver.py check

echo "== the log after the upgrade"
# Expected: Home Assistant's notice for any custom integration, its warning for each wrong password
# the driver sends, and the camera error for the stream the driver requests of a camera that is not there.
bad=$(docker exec "$NAME" cat /config/home-assistant.log | grep -E "ERROR|CRITICAL|Traceback|WARNING.*access_guard" \
      | grep -vE "has not been tested by Home Assistant|Error requesting stream: Camera not found" || true)
if [ -n "$bad" ]; then
    echo "$bad"
    echo "FAIL  the log holds errors or Access Guard warnings"
    exit 1
fi
echo "  ok    no error, and no warning from Access Guard"
