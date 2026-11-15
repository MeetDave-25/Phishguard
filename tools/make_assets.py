"""Regenerates the share-preview image and icons. Needs: pip install playwright (uses your installed Edge/Chrome).
Usage: python tools/make_assets.py
Outputs (in static/): og-image.png (1200x630), icon-192.png, icon-512.png, icon-maskable-512.png, apple-touch-icon.png (180x180)
"""
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
ICON_HTML = """<!doctype html><body style="margin:0;background:#efece4;display:grid;place-items:center;width:{s}px;height:{s}px">
<svg viewBox="0 0 24 24" width="{i}" height="{i}"><path fill="#ff4a1c" d="M12 2l9 3.5V12c0 5-4 8.5-9 10-5-1.5-9-5-9-10V5.5z"/>
<path d="M7.5 12.2l3 3 6-6.4" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg></body>"""

with sync_playwright() as p:
    try:
        b = p.chromium.launch(channel="msedge", headless=True)
    except Exception:
        b = p.chromium.launch(headless=True)
    pg = b.new_page(viewport={"width": 1200, "height": 630})
    pg.goto((ROOT / "tools" / "og_card.html").as_uri())
    pg.evaluate("document.fonts.ready")
    pg.wait_for_timeout(600)
    pg.screenshot(path=str(ROOT / "static" / "og-image.png"))
    for name, size, frac in (("icon-192.png", 192, 0.62), ("icon-512.png", 512, 0.62), ("icon-maskable-512.png", 512, 0.46), ("apple-touch-icon.png", 180, 0.62)):
        pg.set_viewport_size({"width": size, "height": size})
        pg.set_content(ICON_HTML.format(s=size, i=int(size * frac)))
        pg.screenshot(path=str(ROOT / "static" / name))
    b.close()
print("assets written to static/")
