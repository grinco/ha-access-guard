"""Constants for Access Guard."""

from datetime import timedelta

DOMAIN = "access_guard"

SCAN_INTERVAL = timedelta(seconds=30)
# An open app or browser renews its 30-minute access token; used within this is "connected now".
ACTIVE_WINDOW = timedelta(minutes=35)
ACTIVITY_LEN = 25
MAX_ROWS = 40

EVENT_NEW_LOGIN = f"{DOMAIN}_new_login"
EVENT_LOGIN_REMOVED = f"{DOMAIN}_login_removed"

CONF_GEO_PATH = "geo_path"
CONF_HOME_WAN_ENTITY = "home_wan_entity"
DEFAULT_GEO_FILE = "dbip-country-lite.csv.gz"

SERVICE_SIGN_OUT = "sign_out"
SERVICE_SIGN_OUT_USER = "sign_out_user"
SERVICE_UNBAN = "unban"

EVENT_ANOMALY = f"{DOMAIN}_anomaly"
EVENT_UNBANNED = f"{DOMAIN}_unbanned"

CONF_RULES = "rules"
CONF_FAILURES_BEFORE_LOGIN = "failures_before_login"
CONF_SENSITIVE_DOMAINS = "sensitive_domains"
CONF_PERSISTENT_NOTIFICATION = "persistent_notification"
CONF_NOTIFY_SERVICE = "notify_service"

# Actions a browser or app runs by itself under its user, not something the person did.
NOT_A_PERSON = {("system_log", "write")}
