"""
generate_icons.py
─────────────────
Generates PNG icons for the Shadow Warden browser extension.
Requires Pillow: pip install Pillow

Run from the browser-extension directory:
    python generate_icons.py
"""
import math

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    print("Install Pillow first: pip install Pillow")
    raise

SIZES = [16, 32, 48, 128]
ICONS_DIR = "icons"

import os
os.makedirs(ICONS_DIR, exist_ok=True)


def draw_icon(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d   = ImageDraw.Draw(img)

    # Background circle — dark navy
    margin = max(1, size // 16)
    d.ellipse([margin, margin, size - margin, size - margin], fill=(15, 17, 30, 255))

    # Shield shape
    cx, cy = size // 2, size // 2
    r  = size // 2 - margin - 1
    sw = int(r * 0.55)    # shield width half
    sh = int(r * 0.65)    # shield height half

    # Shield points (simplified)
    top    = (cx,          cy - sh)
    tl     = (cx - sw,     cy - sh // 2)
    bl     = (cx - sw,     cy + sh // 4)
    bottom = (cx,          cy + sh)
    br     = (cx + sw,     cy + sh // 4)
    tr     = (cx + sw,     cy - sh // 2)

    shield_pts = [top, tr, br, bottom, bl, tl]
    d.polygon(shield_pts, fill=(59, 130, 246, 255))   # blue shield

    # "W" letter or simple line at larger sizes
    if size >= 32:
        lw = max(1, size // 20)
        # Simplified W: two V shapes
        pad = size // 5
        mid = cy + size // 8
        q1  = cx - sw // 2
        q3  = cx + sw // 2

        pts_w = [
            (cx - sw + pad // 2, cy - sh // 4),
            (q1, mid),
            (cx, cy),
            (q3, mid),
            (cx + sw - pad // 2, cy - sh // 4),
        ]
        d.line(pts_w, fill=(255, 255, 255, 240), width=lw)

    return img


for sz in SIZES:
    icon = draw_icon(sz)
    path = os.path.join(ICONS_DIR, f"icon{sz}.png")
    icon.save(path, "PNG")
    print(f"Generated {path}")

print("All icons generated.")
