#!/usr/bin/env python3
"""Draws the Access Guard brand images: a shield with a keyhole.

    python3 scripts/make_brand.py

Writes custom_components/access_guard/brand/{icon,icon@2x,logo,logo@2x}.png: the images HACS
validates and shows for the integration, served by Home Assistant (components/brands, 2026.x).
Drawn at 4x and downsampled, so edges are smooth without an SVG renderer.
"""

import os

from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "custom_components", "access_guard", "brand")
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
TOP, BOTTOM = (92, 107, 192), (48, 63, 159)       # indigo 400 -> 700
SS = 4


def shield(size):
    """A square transparent image holding the shield and keyhole."""
    n = size * SS
    img = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    # Gradient fill, masked by the shield outline.
    grad = Image.new("RGBA", (n, n))
    gd = ImageDraw.Draw(grad)
    for y in range(n):
        f = y / n
        gd.line([(0, y), (n, y)], fill=tuple(int(TOP[i] + (BOTTOM[i] - TOP[i]) * f) for i in range(3)) + (255,))
    mask = Image.new("L", (n, n), 0)
    md = ImageDraw.Draw(mask)
    m = n * 0.08
    top, mid, tip = n * 0.07, n * 0.52, n * 0.95
    pts = [(n / 2, top - n * 0.015), (n - m, top + n * 0.07), (n - m, mid)]
    # The lower half curves into the point: approximate with a fan of segments.
    steps = 24
    for k in range(1, steps + 1):
        t = k / steps
        x = (n - m) + (n / 2 - (n - m)) * t
        y = mid + (tip - mid) * (t ** 0.7)
        pts.append((x, y))
    left = [(n - px, py) for px, py in reversed(pts[2:])]
    pts += left[1:] + [(m, top + n * 0.07)]
    md.polygon(pts, fill=255)
    img.paste(grad, (0, 0), mask)
    # Keyhole, white.
    d = ImageDraw.Draw(img)
    cx, cy, r = n / 2, n * 0.43, n * 0.115
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill="white")
    d.polygon([(cx - r * 0.45, cy + r * 0.5), (cx + r * 0.45, cy + r * 0.5),
               (cx + r * 0.8, n * 0.74), (cx - r * 0.8, n * 0.74)], fill="white")
    return img.resize((size, size), Image.LANCZOS)


def logo(height, text_rgb):
    """Shield plus wordmark, transparent background."""
    icon = shield(height)
    font = ImageFont.truetype(FONT, int(height * 0.42))
    probe = ImageDraw.Draw(Image.new("RGBA", (1, 1)))
    l, t, r, b = probe.textbbox((0, 0), "Access Guard", font=font)
    w = height + int(height * 0.18) + (r - l) + int(height * 0.08)
    img = Image.new("RGBA", (w, height), (0, 0, 0, 0))
    img.paste(icon, (0, 0), icon)
    ImageDraw.Draw(img).text((height + int(height * 0.18) - l, (height - (b - t)) / 2 - t), "Access Guard",
                             font=font, fill=text_rgb)
    return img


def main():
    os.makedirs(OUT, exist_ok=True)
    shield(256).save(os.path.join(OUT, "icon.png"), optimize=True)
    shield(512).save(os.path.join(OUT, "icon@2x.png"), optimize=True)
    logo(128, (33, 33, 33)).save(os.path.join(OUT, "logo.png"), optimize=True)
    logo(256, (33, 33, 33)).save(os.path.join(OUT, "logo@2x.png"), optimize=True)


if __name__ == "__main__":
    main()
