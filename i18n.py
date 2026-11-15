"""Internationalisation: translation files, /<lang>/ URL prefixes, and translation of analysis results.

* UI strings live in translations/<lang>.json (flat "section.key": "text"). English is the source of truth;
  any key missing in another language falls back to English, so a half-finished language still works.
* Translation values are written by us (not user input), so they may contain a few HTML tags (<em>, <b>, <br>, <a>).
  tests/test_i18n.py enforces that, and that every language keeps the same {placeholders} as English.
* Add a language: add it to LANGS, drop translations/<code>.json next to the others, add its font if it needs one.
"""
import html
import json
import re
from pathlib import Path

from markupsafe import Markup, escape

DIR = Path(__file__).resolve().parent / "translations"
DEFAULT = "en"
# code: (native name, English name, Open Graph locale)
LANGS = {
    "en": ("English", "English", "en_US"),
    "hi": ("हिन्दी", "Hindi", "hi_IN"),
    "gu": ("ગુજરાતી", "Gujarati", "gu_IN"),
    "mr": ("मराठी", "Marathi", "mr_IN"),
    "es": ("Español", "Spanish", "es_ES"),
}
_PREFIXED = [c for c in LANGS if c != DEFAULT]
LANG_RE = re.compile(r"^/(%s)(?:/(.*))?$" % "|".join(_PREFIXED))
_cache: dict = {}


class _Safe(dict):
    def __missing__(self, k):
        return "{" + k + "}"


def load(lang: str) -> dict:
    if lang not in _cache:
        p = DIR / f"{lang}.json"
        _cache[lang] = json.loads(p.read_text("utf-8")) if p.exists() else {}
    return _cache[lang]


def reload() -> None:
    _cache.clear()


def has(lang: str, key: str) -> bool:
    return key in load(lang)


def raw(key: str, lang: str = DEFAULT) -> str:
    v = load(lang).get(key)
    if v is None and lang != DEFAULT:
        v = load(DEFAULT).get(key)
    return v if v is not None else key


def t(key: str, lang: str = DEFAULT, **kw) -> Markup:
    s = raw(key, lang)
    if kw:
        s = s.format_map(_Safe({k: escape(v) for k, v in kw.items()}))
    return Markup(s)


def ta(key: str, lang: str = DEFAULT, **kw) -> Markup:
    """Plain, attribute-safe text (tags stripped, entities decoded, then escaped)."""
    s = raw(key, lang)
    if kw:
        s = s.format_map(_Safe(kw))
    return escape(html.unescape(re.sub(r"<[^>]+>", "", s)))


def plain(key: str, lang: str = DEFAULT, **kw) -> str:
    """Plain text for server messages, JSON and emails."""
    return str(ta(key, lang, **kw)).replace("&amp;", "&").replace("&#39;", "'").replace("&#34;", '"').replace("&lt;", "<").replace("&gt;", ">")


def prefix(lang: str, path: str) -> str:
    """'/about' -> '/hi/about' (English stays unprefixed). Anchors, queries and external URLs pass through."""
    if lang == DEFAULT or lang not in LANGS or not path.startswith("/") or path.startswith("//"):
        return path
    return "/" + lang + path


def js_bundle(lang: str) -> dict:
    out = {k[3:]: v for k, v in load(DEFAULT).items() if k.startswith("js.")}
    out.update({k[3:]: v for k, v in load(lang).items() if k.startswith("js.")})
    return out


def best_language(accept_language: str) -> str:
    """Pick a supported language from an Accept-Language header (used only to SUGGEST, never to redirect)."""
    for part in (accept_language or "").split(","):
        code = part.split(";")[0].strip().lower().split("-")[0]
        if code in LANGS:
            return code
    return DEFAULT


class LangPrefixMiddleware:
    """WSGI: '/hi/about' is served by the '/about' route with environ['pg.lang']='hi'."""

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        m = LANG_RE.match(environ.get("PATH_INFO", ""))
        if m:
            environ["pg.lang"] = m.group(1)
            environ["PATH_INFO"] = "/" + (m.group(2) or "")
        return self.app(environ, start_response)


# ------------------------------------------------------------------ translating analysis results
# (id, title regex, detail regex or None). The regexes pull dynamic values out of the English finding;
# translations are in translations/<lang>.json as f.<id>.t / f.<id>.d with {named} placeholders.
_R = lambda p: re.compile(p, re.S)  # noqa: E731
FINDINGS = [
    ("no_https", _R(r"No HTTPS"), None),
    ("uses_https", _R(r"Uses HTTPS"), None),
    ("ip_host", _R(r"IP address instead of a domain"), None),
    ("mixed_script", _R(r"Look-alike \(mixed-script\) characters"), None),
    ("idn", _R(r"International domain name"), None),
    ("free_host", _R(r"Hosted on a free site-builder platform"), _R(r"Anyone can create a page on (?P<host>\S+) in minutes")),
    ("at_trick", _R(r"'@' hidden in the URL"), None),
    ("shortener", _R(r"URL shortener"), None),
    ("risky_tld", _R(r"Risky domain ending \(\.(?P<tld>[^)]+)\)"), None),
    ("subdomains", _R(r"Too many subdomains"), _R(r"(?P<n>\d+) subdomain levels")),
    ("hyphens", _R(r"Many hyphens in domain"), None),
    ("long_url", _R(r"Very long URL"), _R(r"(?P<n>\d+) characters")),
    ("digits", _R(r"Lots of digits in domain"), None),
    ("official", _R(r"Official (?P<brand>.+) domain"), _R(r"(?P<host>\S+) is a known legitimate domain")),
    ("impersonates", _R(r"Impersonates (?P<brand>.+)"), _R(r"the real site is (?P<real>\S+?)\.$")),
    ("typosquat", _R(r"Typosquat of (?P<brand>.+)"), _R(r"'(?P<label>[^']+)' looks like")),
    ("keywords", _R(r"Sensitive keywords in link"), _R(r"Contains: (?P<kw>.+?)\. Common")),
    ("redirect_param", _R(r"Redirect to another site"), None),
    ("new_domain", _R(r"Very new domain"), _R(r"Registered only (?P<d>\d+) days ago")),
    ("young_domain", _R(r"Young domain"), _R(r"Registered (?P<d>\d+) days ago")),
    ("old_domain", _R(r"Established domain"), _R(r"about (?P<y>\d+) year")),
    ("tls_problem", _R(r"TLS certificate problem"), None),
    ("new_cert", _R(r"Brand-new certificate"), _R(r"issued (?P<d>\d+) days ago")),
    ("dns_block", _R(r"Blocked by Cloudflare security DNS"), None),
    ("gsb", _R(r"Flagged by Google Safe Browsing"), None),
    ("openphish", _R(r"Known phishing site"), None),
    ("ml", _R(r"AI model: hostname resembles known phishing sites"), _R(r"rates this web address (?P<p>\d+)% similar")),
    ("page_pw", _R(r"Page asks for a password"), None),
    ("page_otp", _R(r"Page asks for OTP / card / ID details"), _R(r"Fields detected: (?P<f>.+?)\.")),
    ("exfil_form", _R(r"Form sends data to Telegram/Discord/form service"), None),
    ("cross_post", _R(r"Login form posts to a different website"), _R(r"sent to (?P<h>[^,]+), not")),
    ("insecure_form", _R(r"Form sends secrets without encryption"), None),
    ("exfil_script", _R(r"Script sends data to Telegram/Discord"), None),
    ("pretends", _R(r"Page pretends to be (?P<brand>.+)"), None),
    ("title_brand", _R(r"Page title names (?P<brand>.+?) but the site isn’t .+"), None),
    ("hidden_iframe", _R(r"Hidden iframe from another site"), None),
    ("obfuscated", _R(r"Obfuscated script"), None),
    ("blocks", _R(r"Blocks right-click / paste"), None),
    ("meta_redirect", _R(r"Page silently redirects elsewhere"), None),
    ("nocontent", _R(r"Almost no real content"), None),
    ("long_chain", _R(r"Long redirect chain"), _R(r"(?P<n>\d+) redirects")),
    ("shortened_safe", _R(r"Shortened link: destination looks safe"), _R(r"leads to (?P<h>\S+),")),
    ("redirect_diff", _R(r"Redirects to a different site"), _R(r"ends at (?P<h>\S+?)\.$")),
    ("redirect_bad", _R(r"Redirects to a (?P<kind>dangerous|suspicious) site"), _R(r"goes to (?P<h>[^,]+), which scores (?P<n>\d+)/100")),
    # message (text) rules; detail is 'Matched: “…”', we keep the user's own words
    ("t_urgency", _R(r"Urgency / pressure"), _R(r"Matched: “(?P<m>.*)”")),
    ("t_threat", _R(r"Account threat"), _R(r"Matched: “(?P<m>.*)”")),
    ("t_otp", _R(r"Asks for OTP / PIN / password"), _R(r"Matched: “(?P<m>.*)”")),
    ("t_kyc", _R(r"KYC / verification bait"), _R(r"Matched: “(?P<m>.*)”")),
    ("t_prize", _R(r"Prize / lottery / reward"), _R(r"Matched: “(?P<m>.*)”")),
    ("t_money", _R(r"Money request / payment"), _R(r"Matched: “(?P<m>.*)”")),
    ("t_authority", _R(r"Impersonates authority"), _R(r"Matched: “(?P<m>.*)”")),
    ("t_job", _R(r"Job / investment scam"), _R(r"Matched: “(?P<m>.*)”")),
    ("t_refund", _R(r"Refund / overpayment trick"), _R(r"Matched: “(?P<m>.*)”")),
    ("t_remote", _R(r"Install remote-access app"), _R(r"Matched: “(?P<m>.*)”")),
    ("qr", _R(r"Link hidden inside a QR code"), None),
    ("t_digital", _R(r"Digital arrest scam"), _R(r"Matched: “(?P<m>.*)”")),
    ("t_caps", _R(r"Excessive CAPS"), None),
    ("t_call", _R(r"Asks you to call/WhatsApp a number"), None),
]
ERRORS = [
    ("e_nodns", _R(r"domain does not resolve.*")),
    ("e_connect", _R(r"could not connect.*")),
    ("e_timeout", _R(r"timed out")),
    ("e_redirects", _R(r"too many redirects")),
    ("e_blocked", _R(r"blocked: address is private/internal")),
    ("e_port", _R(r"unusual port (?P<p>\d+) not fetched")),
    ("e_failed", _R(r"inspection failed")),
]


def _finding(f: dict, lang: str) -> None:
    for fid, tre, dre in FINDINGS:
        m = tre.fullmatch(f.get("title", ""))
        if not m:
            continue
        vals = m.groupdict()
        if dre:
            md = dre.search(f.get("detail", ""))
            if md:
                vals.update(md.groupdict())
        if fid == "redirect_bad":
            vals["kind"] = plain(f"f.kind.{vals['kind']}", lang)
        dkey = "f.matched.d" if (fid.startswith("t_") and dre) else f"f.{fid}.d"
        if has(lang, f"f.{fid}.t"):
            f["title"] = plain(f"f.{fid}.t", lang, **vals)
        if has(lang, dkey) and (dre is None or dre.search(f.get("detail", ""))):
            f["detail"] = plain(dkey, lang, **vals)
        return


def _error(msg: str, lang: str) -> str:
    for eid, re_ in ERRORS:
        m = re_.fullmatch(msg or "")
        if m and has(lang, f"f.{eid}"):
            return plain(f"f.{eid}", lang, **m.groupdict())
    return msg


def localize_result(result: dict, lang: str) -> dict:
    """Translate finding titles/details and inspection errors in place. Unknown strings stay English."""
    if lang == DEFAULT or lang not in LANGS:
        return result
    parts = [result] + list(result.get("urls", []))
    for r in parts:
        for f in r.get("findings", []):
            _finding(f, lang)
        ins = r.get("inspection")
        if ins:
            if ins.get("error"):
                ins["error"] = _error(ins["error"], lang)
            for hop in ins.get("chain", []):
                if hop.get("error"):
                    hop["error"] = _error(hop["error"], lang)
    return result
