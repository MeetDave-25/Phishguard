"""Public-site layer: SEO endpoints, legal pages, contact/review forms with spam protection,
moderated testimonials, and OPTIONAL Google tags that stay off unless configured and only run after consent.

Privacy rule baked in: with no PHISHGUARD_GA_ID / PHISHGUARD_ADS_ID set, the site loads nothing from Google
and the legal pages say so. With IDs set, nothing loads until the visitor clicks Accept (see static/site.js).
"""
import hashlib
import json
import os
import re
import smtplib
import threading
import time
import uuid
from collections import defaultdict, deque
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlparse

from flask import Blueprint, Response, jsonify, redirect, render_template, request, url_for
from itsdangerous import BadSignature, URLSafeTimedSerializer

import i18n

bp = Blueprint("site", __name__)
ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
TEMPLATES = ROOT / "templates"

NAME, OWNER, OWNER_URL = "PhishGuard", "Meet G. Dave", "https://meetdave.tech"
LEGAL_UPDATED = "15 November 2026"
OG_ALT = "PhishGuard: Scams look real. Until you look closer. A free scam and phishing link checker."
TOPICS = ["Report a scam PhishGuard missed", "A safe site was wrongly flagged", "Bug or problem",
          "Privacy or data request", "Business or press", "Other"]

# (path, priority, changefreq, template that defines its content)
PAGES = [("/", "1.0", "weekly", "index.html"), ("/about", "0.7", "monthly", "about.html"),
         ("/feedback", "0.4", "monthly", "feedback.html"), ("/contact", "0.4", "monthly", "contact.html"),
         ("/privacy", "0.3", "yearly", "privacy.html"), ("/terms", "0.3", "yearly", "terms.html"),
         ("/cookies", "0.3", "yearly", "cookies.html")]
CRUMB_NAMES = {"/about": "About", "/feedback": "Review", "/contact": "Contact", "/privacy": "Privacy policy",
               "/terms": "Terms of use", "/cookies": "Cookie policy"}


# ------------------------------------------------------------------ configuration (validated: values end up in HTML/CSP)
def _env(name: str, pattern: str) -> str:
    v = os.getenv(name, "").strip()
    return v if v and re.fullmatch(pattern, v) else ""


def config() -> dict:
    return {
        "ga_id": _env("PHISHGUARD_GA_ID", r"G-[A-Z0-9]{4,14}"),
        "ads_id": _env("PHISHGUARD_ADS_ID", r"AW-\d{6,12}"),
        "ads_conv": _env("PHISHGUARD_ADS_CONVERSION", r"[A-Za-z0-9_-]{6,40}"),
        "gsc": _env("PHISHGUARD_GSC_TOKEN", r"[A-Za-z0-9_-]{10,100}"),
        "site_url": _env("PHISHGUARD_SITE_URL", r"https?://[A-Za-z0-9.-]+(:\d{2,5})?").rstrip("/"),
        "force_https": bool(os.getenv("PHISHGUARD_FORCE_HTTPS")),
    }


def csp() -> str:
    c = config()
    script, img, connect, frame = ["'self'"], ["'self'", "data:"], ["'self'"], []
    if c["ga_id"] or c["ads_id"]:  # Google endpoints are allowed ONLY when tags are configured
        script += ["https://www.googletagmanager.com"]
        img += ["https://www.google-analytics.com", "https://www.googletagmanager.com", "https://googleads.g.doubleclick.net",
                "https://www.google.com", "https://www.googleadservices.com"]
        connect += ["https://www.google-analytics.com", "https://*.google-analytics.com", "https://*.analytics.google.com",
                    "https://*.googletagmanager.com", "https://stats.g.doubleclick.net", "https://www.google.com",
                    "https://googleads.g.doubleclick.net"]
        frame += ["https://td.doubleclick.net", "https://www.googletagmanager.com"]
    parts = ["default-src 'self'", "script-src " + " ".join(script), "style-src 'self'", "img-src " + " ".join(img),
             "connect-src " + " ".join(connect), "font-src 'self'", "frame-src " + (" ".join(frame) or "'none'"),
             "object-src 'none'", "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'"]
    if c["force_https"]:
        parts.append("upgrade-insecure-requests")
    return "; ".join(parts)


def base_url() -> str:
    return config()["site_url"] or request.url_root.rstrip("/")


# pages that have translations; INDEXED_TRANSLATED also get hreflang alternates + sitemap entries per language
INDEXED_TRANSLATED = ["/", "/contact", "/feedback"]
ENGLISH_ONLY = {"/about", "/privacy", "/terms", "/cookies"}  # legal/long pages stay English (a wrong legal translation is worse than none)


def current_lang() -> str:
    return request.environ.get("pg.lang", i18n.DEFAULT)


@bp.app_context_processor
def inject():
    c, base = config(), base_url()
    lang, path = current_lang(), request.path
    english_only = path in ENGLISH_ONLY
    canonical = base + (path if english_only else i18n.prefix(lang, path))
    crumbs = [{"@type": "ListItem", "position": 1, "name": "Home", "item": base + i18n.prefix(lang, "/")}]
    if path in CRUMB_NAMES:
        crumbs.append({"@type": "ListItem", "position": 2, "name": CRUMB_NAMES[path], "item": canonical})
    org = {"@context": "https://schema.org", "@graph": [
        {"@type": "Organization", "@id": base + "/#org", "name": NAME, "url": base + "/",
         "logo": base + "/static/icon-512.png", "founder": {"@type": "Person", "name": OWNER, "url": OWNER_URL}},
        {"@type": "WebSite", "@id": base + "/#website", "url": base + "/", "name": NAME, "inLanguage": list(i18n.LANGS),
         "publisher": {"@id": base + "/#org"}}]}
    alts = [{"code": k, "url": base + i18n.prefix(k, path), "og_locale": v[2]} for k, v in i18n.LANGS.items()] if path in INDEXED_TRANSLATED else []
    langs = [{"code": k, "native": v[0], "english": v[1], "url": i18n.prefix(k, path), "current": k == lang} for k, v in i18n.LANGS.items()]
    return {
        "lang": lang, "t": lambda key, **kw: i18n.t(key, lang, **kw), "ta": lambda key, **kw: i18n.ta(key, lang, **kw),
        "L": lambda p: i18n.prefix(lang, p), "has_t": lambda key: i18n.has(lang, key),
        "langs": langs, "cur_lang": {"code": lang, "native": i18n.LANGS[lang][0]},
        "js": i18n.js_bundle(lang),
        "site": {
            "path": path, "name": NAME, "owner": OWNER, "owner_url": OWNER_URL, "year": time.gmtime().tm_year, "updated": LEGAL_UPDATED,
            "canonical": canonical, "og_image": base + "/static/og-image.png", "og_alt": i18n.plain("meta.og_alt", lang),
            "og_locale": i18n.LANGS[lang][2], "alts": alts, "x_default": base + path,
            "english_only": english_only, "english_url": base + path,
            "analytics": bool(c["ga_id"] or c["ads_id"]), "ga_id": c["ga_id"], "ads_id": c["ads_id"], "ads_conv": c["ads_conv"],
            "gsc": c["gsc"], "org_ld": org},
        "crumbs_ld": {"@context": "https://schema.org", "@type": "BreadcrumbList", "itemListElement": crumbs}}


# ------------------------------------------------------------------ content
FAQ_LINKS = {2: "/privacy", 5: "/about#accuracy", 8: "/about"}


def faq_items(analytics: bool, lang: str = i18n.DEFAULT) -> list:
    items = []
    for n in range(1, 9):
        item = {"q": i18n.plain(f"faq.{n}.q", lang), "a": i18n.plain("faq.2.a_opt" if (n == 2 and analytics) else f"faq.{n}.a", lang)}
        if n in FAQ_LINKS:
            item["link"] = (FAQ_LINKS[n], i18n.plain(f"faq.{n}.link", lang))
        items.append(item)
    return items


def faq_ld(items: list) -> dict:
    return {"@context": "https://schema.org", "@type": "FAQPage",
            "mainEntity": [{"@type": "Question", "name": i["q"], "acceptedAnswer": {"@type": "Answer", "text": i["a"]}} for i in items]}


_approved_cache = {"mtime": None, "data": []}


def approved_reviews(limit: int = 6) -> list:
    """Only reviews the owner approved (data/reviews_approved.json). Never fabricated, never auto-published."""
    p = DATA / "reviews_approved.json"
    try:
        m = p.stat().st_mtime
        if _approved_cache["mtime"] != m:
            raw = json.loads(p.read_text("utf-8"))
            clean = []
            for r in raw if isinstance(raw, list) else []:
                try:
                    rating = int(r.get("rating"))
                    comment = str(r.get("comment", "")).strip()
                except (TypeError, ValueError):
                    continue
                if 1 <= rating <= 5 and 10 <= len(comment) <= 600:
                    clean.append({"rating": rating, "comment": comment, "name": str(r.get("name", "")).strip()[:60]})
            _approved_cache.update(mtime=m, data=clean)
        return _approved_cache["data"][:limit]
    except (OSError, ValueError):
        return []


# ------------------------------------------------------------------ pages
@bp.get("/")
def index():
    lang = current_lang()
    items = faq_items(config()["ga_id"] != "" or config()["ads_id"] != "", lang)
    base = base_url()
    app_ld = {"@context": "https://schema.org", "@type": "SoftwareApplication", "name": NAME, "url": base + "/",
              "applicationCategory": "SecurityApplication", "operatingSystem": "Any (web browser)",
              "description": i18n.plain("meta.app_desc", lang), "inLanguage": lang,
              "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
              "author": {"@type": "Person", "name": OWNER, "url": OWNER_URL}}
    return render_template("index.html", faq=items, faq_ld=faq_ld(items), app_ld=app_ld, reviews=approved_reviews())


@bp.get("/about")
def about():
    return render_template("about.html")


@bp.get("/privacy")
def privacy():
    return render_template("privacy.html")


@bp.get("/terms")
def terms():
    return render_template("terms.html")


@bp.get("/cookies")
def cookies():
    return render_template("cookies.html")


@bp.get("/thank-you")
def thank_you():
    kind = request.args.get("for", "contact")
    kind = kind if kind in ("contact", "review") else "contact"
    # the conversion event may only fire after a REAL submission: it needs a fresh, signed token
    try:
        conv = _ser().loads(request.args.get("k", ""), salt="thanks", max_age=600).get("kind") == kind
    except (BadSignature, AttributeError):
        conv = False
    return render_template("thank_you.html", kind=kind, conv=conv)


@bp.app_errorhandler(404)
def not_found(_):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found"}), 404
    return render_template("404.html"), 404


# ------------------------------------------------------------------ installable app (PWA)
@bp.get("/manifest.webmanifest")
def manifest():
    icon = lambda f, sz, purpose="any": {"src": f"/static/{f}", "sizes": sz, "type": "image/png", "purpose": purpose}
    data = {
        "id": "/", "name": "PhishGuard: Scam & Phishing Checker", "short_name": "PhishGuard", "lang": "en", "dir": "ltr",
        "description": "Check any link, message or screenshot for scams. Free and private.",
        "start_url": "/?source=app", "scope": "/", "display": "standalone", "orientation": "portrait",
        "background_color": "#efece4", "theme_color": "#efece4", "categories": ["security", "utilities"],
        "icons": [icon("icon-192.png", "192x192"), icon("icon-512.png", "512x512"), icon("icon-maskable-512.png", "512x512", "maskable")],
        "shortcuts": [{"name": "Check a link", "short_name": "Check", "url": "/#checker", "icons": [icon("icon-192.png", "192x192")]},
                      {"name": "Report a problem", "short_name": "Report", "url": "/contact", "icons": [icon("icon-192.png", "192x192")]}],
        # lets people share a suspicious message from WhatsApp/SMS/browser straight into PhishGuard.
        # The service worker keeps the shared text in the browser; it never reaches our server.
        "share_target": {"action": "/share-target", "method": "POST", "enctype": "multipart/form-data",
                         "params": {"title": "title", "text": "text", "url": "url"}},
    }
    return Response(json.dumps(data), mimetype="application/manifest+json", headers={"Cache-Control": "public, max-age=3600"})


@bp.get("/sw.js")
def service_worker():
    """Served from the site root so it controls the whole site. The cache version changes whenever an asset does."""
    files = ["static/sw.js", "static/style.css", "static/site.js", "static/app.js", "static/story.js", "templates/offline.html"]
    ver = hashlib.sha1("|".join(str(int((ROOT / f).stat().st_mtime)) for f in files if (ROOT / f).exists()).encode()).hexdigest()[:10]
    src = (ROOT / "static" / "sw.js").read_text("utf-8").replace("__VERSION__", ver)
    return Response(src, mimetype="application/javascript", headers={"Cache-Control": "no-cache", "Service-Worker-Allowed": "/"})


@bp.get("/offline")
def offline():
    return render_template("offline.html")


@bp.post("/share-target")
def share_target_fallback():
    """Used only when the service worker isn't active: we never read or keep what was shared."""
    return redirect("/#checker", 303)


# ------------------------------------------------------------------ robots + sitemap
@bp.get("/robots.txt")
def robots():
    body = f"User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /healthz\n\nSitemap: {base_url()}/sitemap.xml\n"
    return Response(body, mimetype="text/plain")


@bp.get("/sitemap.xml")
def sitemap():
    base = base_url()
    shared = (TEMPLATES / "base.html").stat().st_mtime
    rows = []
    for path, prio, freq, tpl in PAGES:
        try:
            ts = max(shared, (TEMPLATES / tpl).stat().st_mtime)
        except OSError:
            ts = shared
        lastmod = time.strftime("%Y-%m-%d", time.gmtime(ts))
        codes = list(i18n.LANGS) if path in INDEXED_TRANSLATED else [i18n.DEFAULT]
        alt = ""
        if len(codes) > 1:
            alt = "".join(f'<xhtml:link rel="alternate" hreflang="{c}" href="{base}{i18n.prefix(c, path)}"/>' for c in codes)
            alt += f'<xhtml:link rel="alternate" hreflang="x-default" href="{base}{path}"/>'
        for c in codes:
            rows.append(f"  <url><loc>{base}{i18n.prefix(c, path)}</loc>{alt}<lastmod>{lastmod}</lastmod>"
                        f"<changefreq>{freq}</changefreq><priority>{prio}</priority></url>")
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" '
           'xmlns:xhtml="http://www.w3.org/1999/xhtml">\n' + "\n".join(rows) + "\n</urlset>\n")
    return Response(xml, mimetype="application/xml")


# ------------------------------------------------------------------ forms + spam protection
_secret_cache = {}
MIN_FILL_SECONDS, TOKEN_MAX_AGE = 3, 2 * 3600
FORM_LIMIT = (5, 3600)  # 5 submissions per IP per hour
_hits: dict = defaultdict(deque)
_lock = threading.Lock()
EMAIL_RE = re.compile(r"[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,24}")
LINK_RE = re.compile(r"https?://|www\.", re.I)


def _secret() -> bytes:
    if "v" in _secret_cache:
        return _secret_cache["v"]
    env = os.getenv("PHISHGUARD_SECRET")
    if env:
        _secret_cache["v"] = env.encode()
    else:  # shared by all workers via a file, so a token made by one worker verifies on another
        DATA.mkdir(exist_ok=True)
        p = DATA / "secret.key"
        try:
            fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.write(fd, os.urandom(32).hex().encode())
            os.close(fd)
        except FileExistsError:
            pass
        for _ in range(20):
            v = p.read_bytes()
            if len(v) >= 64:
                break
            time.sleep(0.05)
        _secret_cache["v"] = v
    return _secret_cache["v"]


def _ser() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(_secret())


def form_token(kind: str) -> str:
    return _ser().dumps({"k": kind, "t": int(time.time())}, salt="form")


def _limited() -> bool:
    max_req, window = FORM_LIMIT
    now, key = time.time(), request.remote_addr
    with _lock:
        q = _hits[key]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= max_req:
            return True
        q.append(now)
        if len(_hits) > 5000:
            for k in [k for k, v in _hits.items() if not v or now - v[-1] > window]:
                _hits.pop(k, None)
    return False


def _same_origin() -> bool:
    src = request.headers.get("Origin") or request.headers.get("Referer")
    if not src or src == "null":
        return True  # some privacy setups send neither; the signed token still protects us
    return urlparse(src).netloc.lower() == request.host.lower()


def _clean(s: str, multiline: bool = False) -> str:
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s or "")
    return s.strip() if multiline else re.sub(r"\s+", " ", s).strip()


def check_spam() -> str:
    """Returns 'ok', 'silent' (a bot: pretend success, store nothing), 'expired', 'origin' or 'rate'."""
    if not _same_origin():
        return "origin"
    if request.form.get("website"):  # honeypot: humans never see or fill this
        return "silent"
    try:
        tok = _ser().loads(request.form.get("t", ""), salt="form", max_age=TOKEN_MAX_AGE)
    except BadSignature:
        return "expired"
    if time.time() - tok.get("t", 0) < MIN_FILL_SECONDS:  # submitted faster than a person can type
        return "silent"
    if _limited():
        return "rate"
    return "ok"


def _store(fname: str, rec: dict) -> None:
    DATA.mkdir(exist_ok=True)
    with _lock, open(DATA / fname, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _notify(subject: str, body: str, reply_to: str = "") -> None:
    host, to = os.getenv("PHISHGUARD_SMTP_HOST"), os.getenv("PHISHGUARD_SMTP_TO")
    if not host or not to:
        return

    def send():
        try:
            m = EmailMessage()
            m["Subject"], m["To"] = subject, to
            m["From"] = os.getenv("PHISHGUARD_SMTP_FROM") or os.getenv("PHISHGUARD_SMTP_USER") or to
            if reply_to and EMAIL_RE.fullmatch(reply_to):
                m["Reply-To"] = reply_to
            m.set_content(body)
            with smtplib.SMTP(host, int(os.getenv("PHISHGUARD_SMTP_PORT", "587")), timeout=15) as s:
                s.starttls()
                if os.getenv("PHISHGUARD_SMTP_USER"):
                    s.login(os.getenv("PHISHGUARD_SMTP_USER"), os.getenv("PHISHGUARD_SMTP_PASS", ""))
                s.send_message(m)
        except Exception:
            pass  # a mail failure must never lose or block the visitor's message (it is already stored)
    threading.Thread(target=send, daemon=True).start()


def _thanks(kind: str):
    return redirect(i18n.prefix(current_lang(), url_for("site.thank_you", **{"for": kind, "k": _ser().dumps({"kind": kind}, salt="thanks")})), 303)


def _form_page(kind: str, form: dict, error: str = "", status: int = 200):
    tpl = "contact.html" if kind == "contact" else "feedback.html"
    return render_template(tpl, token=form_token(kind), form=form, error=error, topics=TOPICS), status


@bp.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "GET":
        return _form_page("contact", {})
    form = {"name": _clean(request.form.get("name", ""))[:80], "email": _clean(request.form.get("email", ""))[:120],
            "topic": request.form.get("topic", "Other"), "message": _clean(request.form.get("message", ""), True)[:2000]}
    spam = check_spam()
    if spam == "silent":
        return _thanks("contact")
    if spam != "ok":
        return _spam_response("contact", form, spam)
    if not EMAIL_RE.fullmatch(form["email"]):
        return _form_page("contact", form, i18n.plain("err.email", current_lang()), 400)
    if len(form["message"]) < 10:
        return _form_page("contact", form, i18n.plain("err.short", current_lang()), 400)
    if len(LINK_RE.findall(form["message"])) > 2:
        return _form_page("contact", form, i18n.plain("err.links_msg", current_lang()), 400)
    if form["topic"] not in TOPICS:
        form["topic"] = "Other"
    rec = {"id": uuid.uuid4().hex[:12], "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **form}
    _store("messages.jsonl", rec)
    _notify(f"[PhishGuard] {form['topic']}", f"From: {form['name'] or '(no name)'} <{form['email']}>\nTopic: {form['topic']}\n\n{form['message']}\n", form["email"])
    return _thanks("contact")


@bp.route("/feedback", methods=["GET", "POST"])
def feedback():
    if request.method == "GET":
        return _form_page("review", {})
    form = {"name": _clean(request.form.get("name", ""))[:60], "email": _clean(request.form.get("email", ""))[:120],
            "rating": request.form.get("rating", ""), "comment": _clean(request.form.get("comment", ""), True)[:600],
            "publish": request.form.get("publish") == "1"}
    spam = check_spam()
    if spam == "silent":
        return _thanks("review")
    if spam != "ok":
        return _spam_response("review", form, spam)
    if form["rating"] not in ("1", "2", "3", "4", "5"):
        return _form_page("review", form, i18n.plain("err.rating", current_lang()), 400)
    if len(form["comment"]) < 10:
        return _form_page("review", form, i18n.plain("err.short", current_lang()), 400)
    if form["email"] and not EMAIL_RE.fullmatch(form["email"]):
        return _form_page("review", form, i18n.plain("err.email_opt", current_lang()), 400)
    if len(LINK_RE.findall(form["comment"])) > 2:
        return _form_page("review", form, i18n.plain("err.links_rev", current_lang()), 400)
    rec = {"id": uuid.uuid4().hex[:12], "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "status": "pending", **{k: form[k] for k in ("name", "email", "comment", "publish")}, "rating": int(form["rating"])}
    _store("reviews.jsonl", rec)
    _notify(f"[PhishGuard] New review ({form['rating']}/5)", f"{form['comment']}\n\nName: {form['name']}\nMay publish: {form['publish']}\nId: {rec['id']}\n", form["email"])
    return _thanks("review")


def _spam_response(kind: str, form: dict, reason: str):
    key = {"expired": "err.expired", "origin": "err.origin", "rate": "err.rate"}.get(reason, "err.generic")
    return _form_page(kind, form, i18n.plain(key, current_lang()), 429 if reason == "rate" else 400)
