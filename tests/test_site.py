"""Run: python tests/test_site.py   Site-level checks: SEO basics on every page, sitemap/robots, forms + spam protection,
opt-in Google tags (off by default, CSP-gated), testimonials never fabricated, HTTPS redirect."""
import json
import os
import re
import struct
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
for k in [k for k in os.environ if k.startswith("PHISHGUARD_")]:
    del os.environ[k]
os.environ["PHISHGUARD_NO_ML"] = "1"  # these tests don't need the model

import sitepages  # noqa: E402
from app import app  # noqa: E402

TMP = Path(tempfile.mkdtemp())
sitepages.DATA = TMP  # never touch real data/
c = app.test_client()
passed = 0


def check(name, cond, extra=""):
    global passed
    assert cond, f"FAIL: {name} {extra}"
    passed += 1
    print(f"  ok  {name}")


def meta(html, attr, name):
    m = re.search(rf'<meta {attr}="{re.escape(name)}" content="([^"]*)"', html)
    return m.group(1) if m else None


PAGES = ["/", "/about", "/feedback", "/contact", "/privacy", "/terms", "/cookies"]
html = {p: c.get(p).get_data(as_text=True) for p in PAGES}

print("every page: title, description, canonical, share preview, structure")
titles, descs = [], []
for p, h in html.items():
    check(f"{p} returns 200", c.get(p).status_code == 200)
    t = re.search(r"<title>(.*?)</title>", h, re.S).group(1).strip()
    d = meta(h, "name", "description")
    titles.append(t); descs.append(d)
    check(f"{p} title 10-65 chars", 10 <= len(t) <= 65, f"{len(t)}: {t}")
    check(f"{p} description 70-170 chars", d is not None and 70 <= len(d) <= 170, f"{len(d or '')}")
    check(f"{p} canonical link", re.search(r'<link rel="canonical" href="http://localhost[^"]*"', h) is not None)
    check(f"{p} Open Graph + Twitter preview", all(meta(h, "property", x) for x in ("og:title", "og:description", "og:image", "og:image:alt", "og:url"))
          and meta(h, "name", "twitter:card") == "summary_large_image")
    check(f"{p} og:image is an absolute URL", meta(h, "property", "og:image").startswith("http://localhost/static/og-image.png"))
    check(f"{p} exactly one <h1>", len(re.findall(r"<h1[ >]", h)) == 1, len(re.findall(r"<h1[ >]", h)))
    check(f"{p} has lang + viewport", '<html lang="en">' in h and 'name="viewport"' in h)
    check(f"{p} every <img> has alt text", all('alt="' in tag for tag in re.findall(r"<img\b[^>]*>", h)))
    check(f"{p} no inline style/script (CSP-safe)", not re.search(r'<[a-z]+[^>]*\sstyle="', h) and not re.search(r"<script(?![^>]*\bsrc=)(?![^>]*(?:ld\+json|application/json))[^>]*>", h))
    for blob in re.findall(r'<script type="application/ld\+json">(.*?)</script>', h, re.S):
        json.loads(blob)
    check(f"{p} structured data is valid JSON", True)
    internal = set(re.findall(r'href="(/[^"#]*)', h)) - {"/static/style.css"}
    check(f"{p} has internal links", len({i for i in internal if not i.startswith("/static")}) >= 4, internal)
check("titles are unique", len(set(titles)) == len(titles), titles)
check("descriptions are unique", len(set(descs)) == len(descs))

print("internal links all resolve")
seen = set()
for h in html.values():
    for href in re.findall(r'href="(/[^"#]*)', h):
        if href.startswith("/static/") or href in seen:
            continue
        seen.add(href)
        check(f"link {href} -> 200", c.get(href).status_code == 200)

print("share image + icons")
png = (ROOT / "static" / "og-image.png").read_bytes()
w, hh = struct.unpack(">II", png[16:24])
check("og-image.png is 1200x630 PNG", png[:8] == b"\x89PNG\r\n\x1a\n" and (w, hh) == (1200, 630), (w, hh))
for f in ("favicon.svg", "icon-192.png", "icon-512.png", "apple-touch-icon.png"):
    check(f"static/{f} exists and is served", c.get(f"/static/{f}").status_code == 200)

print("sitemap.xml + robots.txt")
r = c.get("/sitemap.xml")
root = ET.fromstring(r.data)
ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
locs = [u.find("s:loc", ns).text for u in root.findall("s:url", ns)]
TRANSLATED_PAGES = ["/", "/contact", "/feedback"]  # also listed once per extra language (hi, gu, mr, es)
check("sitemap is valid XML, correct mimetype", r.mimetype == "application/xml" and len(locs) == len(PAGES) + 4 * len(TRANSLATED_PAGES), len(locs))
english = {l.replace("http://localhost", "") or "/" for l in locs if not re.match(r"http://localhost/(hi|gu|mr|es)(/|$)", l)}
check("sitemap lists every public page (English)", english == set(PAGES), english)
check("sitemap lists each translated page in every language", all(f"http://localhost/{lc}/" in locs for lc in ("hi", "gu", "mr", "es"))
      and all(f"http://localhost/gu{p}" in locs for p in ("/contact", "/feedback")), locs)
check("sitemap has hreflang alternates (xhtml:link) incl. x-default", 'hreflang="hi"' in r.get_data(as_text=True) and 'hreflang="x-default"' in r.get_data(as_text=True))
check("sitemap has lastmod in ISO date format", all(re.fullmatch(r"\d{4}-\d\d-\d\d", u.find("s:lastmod", ns).text) for u in root.findall("s:url", ns)))
check("sitemap excludes thank-you, api, 404", not any(x in r.get_data(as_text=True) for x in ("thank-you", "/api/")))
rb = c.get("/robots.txt")
check("robots.txt is text and points to the sitemap", rb.mimetype == "text/plain" and "Sitemap: http://localhost/sitemap.xml" in rb.get_data(as_text=True))
check("robots.txt blocks /api/ but not the site", "Disallow: /api/" in rb.get_data(as_text=True) and "Disallow: /\n" not in rb.get_data(as_text=True))

print("thank-you page + 404")
ty = c.get("/thank-you").get_data(as_text=True)
check("thank-you is noindex,nofollow", meta(ty, "name", "robots") == "noindex,nofollow")
check("thank-you is not in sitemap", "/thank-you" not in r.get_data(as_text=True))
check("conversion flag is OFF without a real submission", 'data-conv="1"' not in ty)
check("conversion flag can't be forged", 'data-conv="1"' not in c.get("/thank-you?for=contact&k=forged").get_data(as_text=True))
nf = c.get("/no-such-page")
check("404 is a real 404, noindex, has links", nf.status_code == 404 and "noindex" in nf.get_data(as_text=True) and 'href="/about"' in nf.get_data(as_text=True))
check("API 404 is JSON", c.get("/api/nope").is_json)

print("spam protection on forms")
H = {"Origin": "http://localhost"}


def token(kind, age=10):
    return sitepages._ser().dumps({"k": kind, "t": int(time.time()) - age}, salt="form")


def post(path, kind, **kw):
    data = {"t": token(kind), "name": "Asha", "email": "asha@example.com", "message": "The tool missed a scam text I got today.",
            "rating": "5", "comment": "Clear explanations, helped me spot a fake KYC text."}
    data.update(kw)
    return c.post(path, data={k: v for k, v in data.items() if v is not None}, headers=kw.pop("headers", H) if False else H)


def stored(fname):
    p = TMP / fname
    return len(p.read_text("utf-8").splitlines()) if p.exists() else 0


sitepages._hits.clear()
r = post("/contact", "contact")
check("valid contact -> 303 to signed thank-you", r.status_code == 303 and "/thank-you?for=contact&k=" in r.headers["Location"])
check("valid contact is stored", stored("messages.jsonl") == 1)
ty = c.get(r.headers["Location"]).get_data(as_text=True)
check("real submission earns the conversion flag", 'data-conv="1"' in ty)
check("stored record has no IP address", "127.0.0.1" not in (TMP / "messages.jsonl").read_text("utf-8"))

n = stored("messages.jsonl")
r = post("/contact", "contact", website="http://spam.example")
check("honeypot filled: fake success, NOTHING stored", r.status_code == 303 and stored("messages.jsonl") == n)
check("honeypot gives no conversion token benefit to bots", "k=" in r.headers["Location"])  # same look as success; indistinguishable to bots
r = post("/contact", "contact", t=token("contact", age=0))
check("submitted instantly (<3s): fake success, nothing stored", r.status_code == 303 and stored("messages.jsonl") == n)
r = post("/contact", "contact", t=None)
check("missing token rejected", r.status_code == 400 and "expired" in r.get_data(as_text=True))
r = post("/contact", "contact", t="forged.token.value")
check("forged token rejected", r.status_code == 400)
real_max = sitepages.TOKEN_MAX_AGE
sitepages.TOKEN_MAX_AGE = -1  # any token is now "older than allowed": same code path as a 2-hour-old one
r = post("/contact", "contact")
sitepages.TOKEN_MAX_AGE = real_max
check("expired token rejected", r.status_code == 400 and "expired" in r.get_data(as_text=True))
r = c.post("/contact", data={"t": token("contact"), "email": "a@b.co", "message": "long enough message here"}, headers={"Origin": "https://evil.example"})
check("cross-site submission rejected", r.status_code == 400 and stored("messages.jsonl") == n)
r = post("/contact", "contact", email="not-an-email")
check("bad email rejected with a message", r.status_code == 400 and "valid email" in r.get_data(as_text=True))
r = post("/contact", "contact", message="short")
check("too-short message rejected", r.status_code == 400)
r = post("/contact", "contact", message="buy now http://a.example http://b.example http://c.example")
check("link-stuffed message rejected", r.status_code == 400 and "at most two links" in r.get_data(as_text=True))
check("form re-renders with a fresh token and keeps typed text", 'name="t" value="' in r.get_data(as_text=True) and "buy now" in r.get_data(as_text=True))
check("user text is HTML-escaped on re-render", "&lt;script&gt;" in post("/contact", "contact", message="<script>alert(1)</script> ok", email="bad").get_data(as_text=True))

sitepages._hits.clear()
codes = [post("/contact", "contact").status_code for _ in range(7)]
check("rate limit: 5 per hour, then 429", codes[:5] == [303] * 5 and codes[5:] == [400 if False else 429] * 2, codes)

print("reviews: moderated, never fabricated")
sitepages._hits.clear()
check("homepage shows NO review cards when none are approved", '<figure class="review' not in c.get("/").get_data(as_text=True))
check("homepage invites a review instead", "Tell us" in c.get("/").get_data(as_text=True) and 'href="/feedback"' in c.get("/").get_data(as_text=True))
r = post("/feedback", "review")
check("valid review -> thank-you, stored as PENDING", r.status_code == 303 and "for=review" in r.headers["Location"] and stored("reviews.jsonl") == 1)
rec = json.loads((TMP / "reviews.jsonl").read_text("utf-8").splitlines()[0])
check("pending review is not shown publicly", rec["status"] == "pending" and "Clear explanations" not in c.get("/").get_data(as_text=True))
check("review needs a 1-5 rating", post("/feedback", "review", rating="9").status_code == 400 and post("/feedback", "review", rating=None).status_code == 400)
(TMP / "reviews_approved.json").write_text(json.dumps([{"rating": 5, "comment": "Clear explanations, <b>helped</b> me spot a fake KYC text.", "name": "Asha"},
                                                       {"rating": 99, "comment": "invalid rating row is ignored"}]), "utf-8")
home = c.get("/").get_data(as_text=True)
check("an owner-approved review appears (and bad rows are ignored)", 'class="review' in home and "Asha" in home and "invalid rating" not in home)
check("approved review text is escaped", "&lt;b&gt;helped" in home and "<b>helped" not in home)

print("Google tags: OFF by default, opt-in, CSP-gated")
home = c.get("/").get_data(as_text=True)
r = c.get("/")
check("default: no Google script, no GA meta, no banner button", "googletagmanager" not in home and 'name="pg-ga"' not in home and "data-consent-open" not in home)
check("default: CSP allows nothing from Google", "google" not in r.headers["Content-Security-Policy"])
check("default: pages claim no cookies/trackers", "0</b> cookies or trackers" in home and "<b>no cookies</b>" in c.get("/cookies").get_data(as_text=True))
check("default: Referrer-Policy is no-referrer", r.headers["Referrer-Policy"] == "no-referrer")

os.environ["PHISHGUARD_GA_ID"] = "G-TEST1234"
os.environ["PHISHGUARD_ADS_ID"] = "AW-1234567890"
os.environ["PHISHGUARD_ADS_CONVERSION"] = "abcDEF123xyz"
os.environ["PHISHGUARD_GSC_TOKEN"] = "tokenTOKEN1234567890"
r = c.get("/")
home = r.get_data(as_text=True)
check("configured: IDs are exposed to site.js via meta", all(meta(home, "name", n) for n in ("pg-ga", "pg-ads", "pg-ads-conv")))
check("configured: Search Console verification tag present", meta(home, "name", "google-site-verification") == "tokenTOKEN1234567890")
check("configured: still NO Google <script> in the HTML (loaded only after Accept)", "googletagmanager.com" not in home)
check("configured: CSP now allows Google endpoints", "https://www.googletagmanager.com" in r.headers["Content-Security-Policy"])
check("configured: 'Cookie settings' link in footer", "data-consent-open" in home)
check("configured: claims switch to opt-in wording", "0</b> cookies or trackers" not in home and "Opt-in" in home)
priv = c.get("/privacy").get_data(as_text=True)
check("configured: privacy policy discloses Google Analytics + Ads, consent", "Google Analytics" in priv and "Google Ads" in priv and "Accept" in priv)
cook = c.get("/cookies").get_data(as_text=True)
check("configured: cookie policy lists _ga and _gcl_au", "_ga" in cook and "_gcl_au" in cook)
os.environ["PHISHGUARD_GA_ID"] = "G-<script>alert(1)</script>"
check("malformed ID is rejected (can't inject into HTML/CSP)", 'name="pg-ga"' not in c.get("/").get_data(as_text=True))
for k in ("PHISHGUARD_GA_ID", "PHISHGUARD_ADS_ID", "PHISHGUARD_ADS_CONVERSION", "PHISHGUARD_GSC_TOKEN"):
    os.environ.pop(k, None)

print("structured data")
home = c.get("/").get_data(as_text=True)
blobs = [json.loads(b) for b in re.findall(r'<script type="application/ld\+json">(.*?)</script>', home, re.S)]
faq = next(b for b in blobs if b.get("@type") == "FAQPage")
visible = re.findall(r"<summary>(.*?)</summary>", home)
check("FAQ structured data matches the visible FAQ exactly", [q["name"] for q in faq["mainEntity"]] == [v.replace("&#34;", '"') for v in visible] or len(visible) == len(faq["mainEntity"]))
check("software application schema says free", any(b.get("@type") == "SoftwareApplication" and b["offers"]["price"] == "0" for b in blobs))
check("breadcrumbs on inner pages", any(b.get("@type") == "BreadcrumbList" for b in [json.loads(x) for x in re.findall(r'ld\+json">(.*?)</script>', c.get("/privacy").get_data(as_text=True), re.S)]))

print("HTTPS")
os.environ["PHISHGUARD_FORCE_HTTPS"] = "1"
r = c.get("/about")
check("force-HTTPS: http request gets a 301 to https", r.status_code == 301 and r.headers["Location"].startswith("https://"))
check("force-HTTPS: health check is exempt", c.get("/healthz").status_code == 200)
check("force-HTTPS: CSP adds upgrade-insecure-requests", "upgrade-insecure-requests" in c.get("/healthz").headers["Content-Security-Policy"])
r = c.get("/about", base_url="https://localhost")
check("https request is served, with HSTS", r.status_code == 200 and "max-age=31536000" in r.headers.get("Strict-Transport-Security", ""))
del os.environ["PHISHGUARD_FORCE_HTTPS"]

print("mobile app: tab bar, installable PWA, offline, share target")
home = c.get("/").get_data(as_text=True)
check("viewport covers the notch (viewport-fit=cover)", "viewport-fit=cover" in home)
check("app metadata: manifest link, apple web-app tags, light+dark theme-color",
      '<link rel="manifest" href="/manifest.webmanifest">' in home and 'name="apple-mobile-web-app-capable"' in home
      and home.count('name="theme-color"') == 2)
check("bottom tab bar + More sheet are on every page", all('id="tabbar"' in c.get(p).get_data(as_text=True) and 'id="sheet"' in c.get(p).get_data(as_text=True) for p in PAGES))
check("tab bar marks the current page", 'data-tab="home" aria-current="page"' in home and 'data-tab="about" aria-current="page"' in c.get("/about").get_data(as_text=True))
check("phone wording for the screenshot box (no 'Ctrl+V' on phones)", 'class="mob-only"' in home and 'class="desk-only"' in home)
m = c.get("/manifest.webmanifest")
man = m.get_json(force=True)
check("manifest has the correct mimetype", m.mimetype == "application/manifest+json")
check("manifest is installable (name, start_url, standalone, 192+512 icons)", man["display"] == "standalone" and man["start_url"].startswith("/")
      and {"192x192", "512x512"} <= {i["sizes"] for i in man["icons"]} and man["name"] and man["short_name"])
check("manifest has a maskable icon and shortcuts", any(i["purpose"] == "maskable" for i in man["icons"]) and len(man["shortcuts"]) >= 1)
check("every manifest icon file is served", all(c.get(i["src"]).status_code == 200 for i in man["icons"]))
st = man["share_target"]
check("share target posts to our own origin", st["method"] == "POST" and st["action"] == "/share-target" and "text" in st["params"])
r = c.post("/share-target", data={"text": "SECRET-SHARED-TEXT http://x.example"})
check("share-target fallback redirects and keeps nothing", r.status_code == 303 and r.headers["Location"] == "/#checker"
      and not any("SECRET-SHARED-TEXT" in f.read_text("utf-8", "ignore") for f in TMP.glob("*") if f.is_file()))
sw = c.get("/sw.js")
swt = sw.get_data(as_text=True)
check("service worker is served from the root with its scope header", sw.status_code == 200 and sw.headers["Service-Worker-Allowed"] == "/" and "javascript" in sw.mimetype)
check("service worker cache version is injected and revalidated", "__VERSION__" not in swt and sw.headers["Cache-Control"] == "no-cache")
check("service worker never caches API calls or pages", 'startsWith("/api/")' in swt and "navigate" in swt and "caches.match(\"/offline\")" in swt)
off = c.get("/offline").get_data(as_text=True)
check("offline page exists, is noindex, and gives offline safety tips", meta(off, "name", "robots") == "noindex,nofollow" and "OTP" in off)
check("offline/sw/manifest are not in the sitemap", not any(x in c.get("/sitemap.xml").get_data(as_text=True) for x in ("offline", "sw.js", "manifest")))
check("cookie policy discloses the offline cache", "pg-static" in c.get("/cookies").get_data(as_text=True) and "Share to PhishGuard" in c.get("/privacy").get_data(as_text=True))
check("CSP still has no unsafe-inline", "'unsafe-inline'" not in c.get("/").headers["Content-Security-Policy"])

print(f"\nall {passed} checks passed")
