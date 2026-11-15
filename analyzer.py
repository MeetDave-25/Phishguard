"""PhishGuard analyzer: rule-based scam / phishing detection for URLs and messages."""
import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs

import mlmodel

ML_FLOOR, ML_MAX = 0.5, 60  # model contributes 0..60 points once p > 0.5

URL_RE = re.compile(r"(?i)\b((?:https?://|www\.)[^\s<>\"']+|(?:[a-z0-9-]+\.)+(?:com|net|org|in|xyz|top|info|co|io|ly|link|click|live|online|site|shop|support|app)(?:/[^\s<>\"']*)?)")

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy",
              "ow.ly", "shorturl.at", "tiny.cc", "rebrand.ly", "buff.ly"}

FREE_HOSTS = {"netlify.app", "pages.dev", "workers.dev", "weebly.com", "onrender.com", "vercel.app", "github.io", "web.app",
              "firebaseapp.com", "blogspot.com", "wixsite.com", "glitch.me", "herokuapp.com", "000webhostapp.com", "godaddysites.com",
              "framer.app", "framer.website", "webflow.io", "myshopify.com", "square.site", "carrd.co", "sites.google.com",
              "r2.dev", "repl.co", "replit.app", "surge.sh", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "duckdns.org",
              "gitbook.io", "notion.site", "typedream.app", "wordpress.com", "weeblysite.com", "jimdofree.com", "strikingly.com"}

RISKY_TLDS = {"xyz", "top", "click", "link", "live", "online", "site", "shop", "support",
              "work", "zip", "mov", "gq", "tk", "ml", "cf", "ga", "icu", "buzz", "rest", "cam"}

# brand -> legitimate registrable domains
BRANDS = {
    # global
    "paypal": ["paypal.com"], "google": ["google.com", "gmail.com", "google.co.in"], "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "apple": ["apple.com", "icloud.com"], "amazon": ["amazon.com", "amazon.in", "amazonpay.in"], "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com"], "instagram": ["instagram.com"], "whatsapp": ["whatsapp.com"],
    "telegram": ["telegram.org", "t.me", "telegram.me", "telegram.dog"], "linkedin": ["linkedin.com"], "dropbox": ["dropbox.com"],
    "binance": ["binance.com"], "coinbase": ["coinbase.com"], "dhl": ["dhl.com"], "fedex": ["fedex.com"],
    "youtube": ["youtube.com"], "spotify": ["spotify.com"], "hotstar": ["hotstar.com"], "truecaller": ["truecaller.com"],
    # Indian banks
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com"], "hdfc": ["hdfcbank.com", "hdfc.com", "hdfclife.com"],
    "icici": ["icicibank.com", "icicilombard.com", "iciciprulife.com"], "axis": ["axisbank.com"], "kotak": ["kotak.com", "kotakbank.com"],
    "pnb": ["pnbindia.in", "netpnb.com"], "bankofbaroda": ["bankofbaroda.in", "bankofbaroda.com"], "canara": ["canarabank.com"],
    "unionbank": ["unionbankofindia.co.in"], "indusind": ["indusind.com"], "yesbank": ["yesbank.in"], "idfcfirst": ["idfcfirstbank.com"],
    "bandhan": ["bandhanbank.com"], "federalbank": ["federalbank.co.in"], "indianbank": ["indianbank.in"], "rbl": ["rblbank.com"],
    "rbi": ["rbi.org.in"], "npci": ["npci.org.in"], "bhim": ["bhimupi.org.in", "npci.org.in"],
    # payments / fintech
    "paytm": ["paytm.com", "paytmbank.com"], "phonepe": ["phonepe.com"], "gpay": ["pay.google.com"], "mobikwik": ["mobikwik.com"],
    "freecharge": ["freecharge.in"], "razorpay": ["razorpay.com"], "cred": ["cred.club"], "zerodha": ["zerodha.com"],
    "groww": ["groww.in"], "upstox": ["upstox.com"], "angelone": ["angelone.in", "angelbroking.com"],
    # government
    "incometax": ["incometax.gov.in", "incometaxindia.gov.in"], "uidai": ["uidai.gov.in"], "aadhaar": ["uidai.gov.in"],
    "epfo": ["epfindia.gov.in"], "parivahan": ["parivahan.gov.in"], "digilocker": ["digilocker.gov.in"], "irctc": ["irctc.co.in"],
    "indiapost": ["indiapost.gov.in"], "gst": ["gst.gov.in"], "umang": ["umang.gov.in"], "lic": ["licindia.in"],
    # telecom
    "jio": ["jio.com"], "airtel": ["airtel.in", "airtel.com"], "bsnl": ["bsnl.co.in"],
    # shopping / services
    "flipkart": ["flipkart.com"], "myntra": ["myntra.com"], "meesho": ["meesho.com"], "nykaa": ["nykaa.com"], "ajio": ["ajio.com"],
    "swiggy": ["swiggy.com"], "zomato": ["zomato.com"], "blinkit": ["blinkit.com"], "zepto": ["zeptonow.com"],
    "bookmyshow": ["bookmyshow.com"], "makemytrip": ["makemytrip.com"], "ola": ["olacabs.com"], "uber": ["uber.com"],
    "naukri": ["naukri.com"], "olx": ["olx.in"], "delhivery": ["delhivery.com"], "bluedart": ["bluedart.com"],
}

URL_KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "confirm", "banking",
                "wallet", "password", "kyc", "suspend", "unlock", "claim", "reward", "refund", "invoice"]

TWO_PART_TLDS = {"co.in", "co.uk", "com.au", "co.jp", "com.br", "org.in", "net.in", "gov.in", "ac.in", "co.za"}

# (label, regex, weight, advice)
TEXT_RULES = [
    ("Urgency / pressure", r"\b(urgent|immediately|within \d+ (hours?|minutes?)|last warning|act now|expires? (today|soon)|final notice)\b", 12),
    ("Account threat", r"\b(account|card|sim|number|upi|wallet)\b.{0,40}\b(blocked|suspended|deactivated|locked|closed|disabled)\b", 18),
    ("Asks for OTP / PIN / password", r"\b(otp|cvv|pin|password|passcode|one[- ]time)\b.{0,40}\b(share|send|enter|provide|tell|reply)\b|\b(share|send|enter|provide|tell|reply)\b.{0,40}\b(otp|cvv|pin|password)\b", 28),
    ("KYC / verification bait", r"\b(kyc|re-?verify|verify your (account|identity|details)|update your (details|kyc|pan|aadhaar))\b", 16),
    ("Prize / lottery / reward", r"\b(you (have )?won|lottery|prize|lucky (draw|winner)|congratulations|cashback|free gift|claim (your )?(reward|prize))\b", 18),
    ("Money request / payment", r"\b(send|transfer|pay)\b.{0,30}(₹|rs\.?|inr|usd|\$|bitcoin|btc|gift ?card)|\b(processing fee|registration fee|customs fee)\b", 18),
    ("Impersonates authority", r"\b(police|cbi|customs|income tax|rbi|court|arrest warrant|fedex|dhl|trai)\b.{0,60}\b(case|parcel|notice|fine|arrest|drugs|illegal)\b", 22),
    ("Job / investment scam", r"\b(work from home|part[- ]time job|earn (₹|rs\.?|\$)?\s?\d+|guaranteed returns?|double your money|crypto (investment|signal)|task.{0,10}(earn|commission))\b", 18),
    ("Refund / overpayment trick", r"\b(refund|reversal|wrongly (sent|credited)|accidentally (sent|transferred))\b", 10),
    ("Install remote-access app", r"\b(anydesk|teamviewer|quicksupport|rustdesk)\b", 26),
]


def _registrable(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in TWO_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _normalize_homoglyphs(s: str) -> str:
    table = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
    s = s.translate(table)
    return s.replace("rn", "m").replace("vv", "w")


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def is_public_host(host: str) -> bool:
    """SSRF guard: only allow deep-scan network calls to publicly routable addresses (never localhost/LAN/cloud metadata)."""
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        return bool(infos) and all(ipaddress.ip_address(i[4][0]).is_global for i in infos)
    except Exception:
        return False


def _tls_info(host: str, timeout=4):
    """Return (issued_days_ago | None, error | None). Best-effort live TLS check."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
        nb = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - nb).days, None
    except ssl.SSLCertVerificationError as e:
        return None, f"Invalid certificate ({e.verify_message})"
    except Exception:
        return None, None


def _domain_age_days(domain: str):
    """Domain age via RDAP (free, keyless); falls back to python-whois if installed."""
    try:
        import json
        import urllib.request
        req = urllib.request.Request(f"https://rdap.org/domain/{domain}", headers={"Accept": "application/rdap+json", "User-Agent": "PhishGuard/1.0"})
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.load(r)
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration":
                created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                return (datetime.now(timezone.utc) - created).days
    except Exception:
        pass
    try:
        # pyrefly: ignore[missing-import]
        import whois
        created = whois.whois(domain).creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - created).days
    except Exception:
        pass
    return None


def normalize_url(raw: str) -> str:
    raw = raw.strip().rstrip(".,;)")
    if not re.match(r"(?i)^[a-z][a-z0-9+.-]*://", raw):
        raw = "http://" + raw
    return raw


def analyze_url(raw: str, live: bool = False) -> dict:
    url = normalize_url(raw)
    findings = []  # {"level": "high|medium|low|good", "title", "detail", "points"}
    score = 0

    def add(level, title, detail, points=0):
        nonlocal score
        score += points
        findings.append({"level": level, "title": title, "detail": detail, "points": points})

    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
    except ValueError:
        return {"type": "url", "input": raw, "score": 70, "verdict": "suspicious",
                "findings": [{"level": "high", "title": "Malformed URL", "detail": "This URL could not be parsed.", "points": 70}]}

    if not host:
        return {"type": "url", "input": raw, "score": 50, "verdict": "suspicious",
                "findings": [{"level": "medium", "title": "No hostname", "detail": "No valid domain was found.", "points": 50}]}

    reg = _registrable(host)
    tld = host.rsplit(".", 1)[-1]
    label = reg.split(".")[0]

    # --- scheme
    if p.scheme == "http" and not raw.lower().startswith("https"):
        add("medium", "No HTTPS", "The link uses plain HTTP, so anything you type can be intercepted.", 10)
    elif p.scheme == "https":
        add("good", "Uses HTTPS", "Encrypted connection (note: scammers use HTTPS too, so this alone is not proof of safety).", 0)

    # --- IP host
    try:
        ipaddress.ip_address(host)
        add("high", "IP address instead of a domain", "Legitimate services almost never ask you to log in on a raw IP address.", 30)
    except ValueError:
        pass

    # --- punycode / non-ascii
    if "xn--" in host or any(ord(c) > 127 for c in host):
        try:
            decoded = host.encode("ascii").decode("idna") if "xn--" in host else host
        except (UnicodeError, UnicodeDecodeError):
            decoded = host
        letters = [c for c in decoded if c.isalpha()]
        latin = sum(1 for c in letters if c.isascii())
        if latin and latin < len(letters):  # mixes Latin with another script: classic homograph attack
            add("high", "Look-alike (mixed-script) characters", "The domain mixes alphabets (e.g. Latin + Cyrillic) so letters imitate real ones.", 30)
        else:  # fully non-Latin domains are normal for non-English sites
            add("low", "International domain name", "Uses non-English characters. Common for legitimate sites too, so only a weak signal.", 6)

    # --- free hosting / site-builder platforms: anyone can publish a page here in minutes
    if host != reg and reg in FREE_HOSTS:
        add("medium", "Hosted on a free site-builder platform", f"Anyone can create a page on {reg} in minutes; scammers abuse it. A real company login would use its own domain.", 16)

    # --- @ trick
    if "@" in (p.netloc or ""):
        add("high", "'@' hidden in the URL", "Everything before '@' is ignored by browsers, a classic trick to disguise the real destination.", 28)

    # --- shorteners
    if host in SHORTENERS:
        add("medium", "URL shortener", "The real destination is hidden. Expand the link before opening.", 18)

    # --- risky TLD
    if tld in RISKY_TLDS:
        add("medium", f"Risky domain ending (.{tld})", "This extension is heavily abused for throwaway scam sites.", 14)

    # --- subdomain depth / hyphens / length
    sub_count = max(0, len(host.split(".")) - len(reg.split(".")))
    if sub_count >= 3:
        add("medium", "Too many subdomains", f"{sub_count} subdomain levels. Scammers bury a brand name in front of the real domain.", 14)
    if label.count("-") >= 2:
        add("medium", "Many hyphens in domain", "Domains like 'secure-login-bank-verify' are typical of phishing.", 12)
    if len(url) > 100:
        add("low", "Very long URL", f"{len(url)} characters, long URLs often hide the real destination.", 6)
    if re.search(r"\d{5,}", label):
        add("low", "Lots of digits in domain", "Randomly generated domains often contain long number strings.", 8)

    # --- brand impersonation
    flagged_brand = False
    norm_host = _normalize_homoglyphs(host)
    for brand, legit in BRANDS.items():
        if reg in legit:
            flagged_brand = True  # genuine, skip
            add("good", f"Official {brand.title()} domain", f"{reg} is a known legitimate domain.", -15)
            break
        # short brands (sbi, jio, lic...) must match a whole token to avoid false hits like "taxis"
        brand_in_host = (brand in re.split(r"[-.]", norm_host)) if len(brand) <= 4 else (brand in norm_host.replace("-", "").replace(".", ""))
        if brand_in_host:
            add("high", f"Impersonates {brand.title()}", f"'{brand}' appears in the address, but the real site is {legit[0]}.", 35)
            flagged_brand = True
            break
        # typosquat: small edit distance to the brand label
        if len(label) >= 5 and 0 < _levenshtein(_normalize_homoglyphs(label), brand) <= 1 and label not in {b for l in legit for b in [l.split('.')[0]]}:
            add("high", f"Typosquat of {brand.title()}", f"'{label}' looks like '{brand}' with a small change.", 35)
            flagged_brand = True
            break

    # --- keywords in path/host
    haystack = (host + p.path + (p.query or "")).lower()
    hits = [k for k in URL_KEYWORDS if k in haystack]
    if hits and not (flagged_brand and any(f["level"] == "good" for f in findings)):
        add("medium" if len(hits) > 1 else "low", "Sensitive keywords in link",
            "Contains: " + ", ".join(hits[:5]) + ". Common in credential-harvesting pages.", min(6 * len(hits), 16))

    # --- redirect params
    q = parse_qs(p.query)
    if any(k.lower() in ("url", "redirect", "redir", "next", "continue", "dest", "return") and v and v[0].startswith("http") for k, v in q.items()):
        add("medium", "Redirect to another site", "The link forwards you to a different address.", 14)

    # --- live checks (network)
    if live and not findings_has(findings, "IP address") and is_public_host(host):
        age = _domain_age_days(reg)
        if age is not None:
            if age < 30:
                add("high", "Very new domain", f"Registered only {age} days ago. Most phishing sites live less than a month.", 30)
            elif age < 180:
                add("medium", "Young domain", f"Registered {age} days ago.", 10)
            else:
                add("good", "Established domain", f"Registered about {age // 365} year(s) ago.", -8)
        if p.scheme == "https":
            days, err = _tls_info(host)
            if err:
                add("high", "TLS certificate problem", err, 25)
            elif days is not None and days < 14:
                add("low", "Brand-new certificate", f"Certificate issued {days} days ago.", 6)

    # --- ML hostname model (offline). Skipped for verified brand domains. Weighted, never decisive alone.
    if not any(f["level"] == "good" and f["title"].startswith("Official") for f in findings):
        p = mlmodel.predict_proba(url)
        if p is not None and p > ML_FLOOR:
            pts = round(ML_MAX * (p - ML_FLOOR) / (1 - ML_FLOOR))
            level = "high" if p >= 0.9 else "medium" if p >= 0.7 else "low"
            add(level, "AI model: hostname resembles known phishing sites",
                f"A model trained on real phishing data rates this web address {round(p * 100)}% similar to phishing hosts.", pts)

    score = max(0, min(100, score))
    return {"type": "url", "input": raw, "host": host, "score": score, "verdict": verdict(score), "findings": findings}


def findings_has(findings, text):
    return any(text in f["title"] for f in findings)


def verdict(score: int) -> str:
    if score >= 55:
        return "dangerous"
    if score >= 25:
        return "suspicious"
    return "safe"


def analyze_text(text: str, live: bool = False) -> dict:
    findings, score = [], 0
    for label, pattern, weight in TEXT_RULES:
        m = re.search(pattern, text, re.I | re.S)
        if m:
            snippet = re.sub(r"\s+", " ", m.group(0))[:80]
            findings.append({"level": "high" if weight >= 20 else "medium", "title": label,
                             "detail": f"Matched: “{snippet}”", "points": weight})
            score += weight

    if re.search(r"[A-Z]{6,}.*[A-Z]{6,}", text) and len(text) > 40:
        findings.append({"level": "low", "title": "Excessive CAPS", "detail": "Shouting text is a pressure tactic.", "points": 5})
        score += 5
    if re.search(r"(?<!\d)\+?\d{10,13}(?!\d)", text) and re.search(r"\b(call|whatsapp|contact)\b", text, re.I):
        findings.append({"level": "low", "title": "Asks you to call/WhatsApp a number", "detail": "Scammers move victims off official channels.", "points": 8})
        score += 8

    urls, seen = [], set()
    for m in URL_RE.finditer(text):
        u = m.group(1).rstrip(".,;)")
        if u.lower() not in seen and not re.fullmatch(r"[\d.]+", u):
            seen.add(u.lower())
            urls.append(u)
    url_results = [analyze_url(u, live) for u in urls[:8]]
    result = {"type": "message", "text_score": min(100, score), "has_text_flags": bool(findings),
              "findings": findings, "urls": url_results}
    rescore_message(result)
    return result


def rescore_message(result: dict) -> None:
    """Combine the text-only score with the worst link score. Call again after links are re-scored (inspection)."""
    score = result["text_score"]
    worst = max((r["score"] for r in result["urls"]), default=0)
    score += int(worst * 0.6)
    if worst >= 25 and result["has_text_flags"]:  # text pressure + risky link is a very strong combo
        score += 10
    if worst >= 90:
        score = max(score, 90)
    result["score"] = max(0, min(100, score))
    result["verdict"] = verdict(result["score"])


def analyze(user_input: str, live: bool = False) -> dict:
    s = user_input.strip()
    if not s:
        return {"error": "Please paste a link or message."}
    if len(s) > 5000:
        s = s[:5000]
    # single token that looks like a URL -> URL mode, otherwise message mode
    if " " not in s and "\n" not in s and (URL_RE.fullmatch(s) or "." in s):
        return analyze_url(s, live)
    return analyze_text(s, live)
