"""Browser test for automatic language switching. Needs: pip install playwright (uses installed Edge), and the server running:
    python app.py     then     python tests/browser_lang.py [http://127.0.0.1:5000]
"""
import sys

from playwright.sync_api import sync_playwright

sys.stdout.reconfigure(encoding="utf-8")
BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"
passed = 0


def check(name, cond, extra=""):
    global passed
    assert cond, f"FAIL: {name} {extra}"
    passed += 1
    print(f"  ok  {name}")


def visit(b, locale, path="/", langs=None, ctx=None, wait=900):
    ctx = ctx or b.new_context(locale=locale)
    if langs:  # full Accept-Language style list, e.g. ["en-IN", "hi"]
        ctx.add_init_script(f"Object.defineProperty(navigator,'languages',{{get:()=>{langs!r}}});Object.defineProperty(navigator,'language',{{get:()=>{langs[0]!r}}});")
    pg = ctx.new_page()
    pg.goto(BASE + path, wait_until="networkidle")
    pg.wait_for_timeout(wait)
    return ctx, pg


with sync_playwright() as p:
    b = p.chromium.launch(channel="msedge", headless=True)

    print("first visit, browser language decides")
    for loc, code in (("hi-IN", "hi"), ("gu-IN", "gu"), ("mr-IN", "mr"), ("es-ES", "es")):
        ctx, pg = visit(b, loc)
        check(f"{loc} browser: / switches to /{code}/", pg.url.rstrip("/").endswith(f"/{code}") and pg.evaluate("document.documentElement.lang") == code, pg.url)
        check(f"{loc}: a 'back to English' notice is shown in {code}", pg.locator(".toast").count() == 1 and pg.locator(".toast a").get_attribute("hreflang") == "en")
        ctx.close()
    ctx, pg = visit(b, "en-US")
    check("English browser stays on the English page, no notice", pg.url.rstrip("/") == BASE and pg.locator(".toast").count() == 0, pg.url)
    ctx.close()
    ctx, pg = visit(b, "fr-FR")
    check("an unsupported language (French) stays English", pg.url.rstrip("/") == BASE)
    ctx.close()
    ctx, pg = visit(b, "en-IN", langs=["en-IN", "hi"])
    check("English listed FIRST means stay (Hindi second does not override)", pg.url.rstrip("/") == BASE, pg.url)
    ctx.close()
    ctx, pg = visit(b, "hi-IN", langs=["hi-IN", "en-US"])
    check("Hindi listed first (English second) switches to Hindi", "/hi/" in pg.url, pg.url)
    ctx.close()

    print("remembering the choice")
    ctx, pg = visit(b, "gu-IN")
    check("auto-switched to Gujarati and remembered", pg.evaluate("localStorage.getItem('pg_lang')") == "gu")
    pg.goto(BASE + "/", wait_until="networkidle"); pg.wait_for_timeout(700)
    check("next visit to / goes straight to Gujarati", "/gu/" in pg.url and pg.locator(".toast").count() == 0, pg.url)
    pg.click(".toast a") if pg.locator(".toast a").count() else None
    pg.goto(BASE + "/gu/", wait_until="networkidle"); pg.wait_for_timeout(300)
    pg.click("#lang summary"); pg.click("#lang a[hreflang=en]"); pg.wait_for_load_state("networkidle"); pg.wait_for_timeout(700)
    check("choosing English in the switcher lands on the English page", pg.url.rstrip("/") == BASE and pg.evaluate("document.documentElement.lang") == "en", pg.url)
    check("...and remembers English", pg.evaluate("localStorage.getItem('pg_lang')") == "en")
    pg.goto(BASE + "/", wait_until="networkidle"); pg.wait_for_timeout(700)
    check("a Gujarati browser is NOT switched again after choosing English", pg.url.rstrip("/") == BASE and pg.locator(".toast").count() == 0, pg.url)
    pg.goto(BASE + "/contact", wait_until="networkidle"); pg.wait_for_timeout(500)
    check("English choice also holds on /contact", pg.url.endswith("/contact") and "/gu/" not in pg.url)
    ctx.close()

    ctx, pg = visit(b, "gu-IN")
    pg.click(".toast a"); pg.wait_for_load_state("networkidle"); pg.wait_for_timeout(700)
    check("the notice's 'Back to English' link works and sticks", pg.url.rstrip("/") == BASE and pg.evaluate("localStorage.getItem('pg_lang')") == "en", pg.url)
    ctx.close()

    print("other pages and flows")
    ctx, pg = visit(b, "hi-IN", path="/contact")
    check("/contact switches to /hi/contact (query-free)", pg.url.endswith("/hi/contact"), pg.url)
    ctx.close()
    ctx, pg = visit(b, "hi-IN", path="/privacy")
    check("English-only pages (/privacy) are NOT redirected", pg.url.endswith("/privacy") and "/hi/" not in pg.url, pg.url)
    ctx.close()
    ctx, pg = visit(b, "hi-IN", path="/?shared=1#checker")
    check("?shared=1 and #hash survive the switch (share-target keeps working)", "/hi/" in pg.url and "shared" in pg.url or pg.url.endswith("#checker"), pg.url)
    ctx.close()
    ctx, pg = visit(b, "hi-IN", path="/hi/")
    check("a page already in Hindi is never redirected or given a notice", pg.url.rstrip("/").endswith("/hi") and pg.locator(".toast").count() == 0, pg.url)
    ctx.close()
    ctx, pg = visit(b, "hi-IN", path="/about")
    check("a search engine-style direct visit to an English-only page stays", "/hi/" not in pg.url)
    ctx.close()

    print("search engines")
    ctx = b.new_context(locale="en-US", user_agent="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
    pg = ctx.new_page(); pg.goto(BASE + "/", wait_until="networkidle"); pg.wait_for_timeout(600)
    check("Googlebot-like visitor (English, no preference) sees the English page", pg.url.rstrip("/") == BASE)
    ctx.close()
    b.close()
print(f"\nall {passed} checks passed")
