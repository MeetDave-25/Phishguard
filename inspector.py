"""Link unmasking + safe page inspection.

Follows redirects and reads (never executes) the destination page's HTML to spot credential-harvesting signs:
login/OTP/card forms posting to another domain, Telegram/Discord exfiltration, hidden iframes, brand impersonation,
obfuscated scripts, hidden redirects.

Safety design (we are connecting to hostile servers on a user's behalf):
 * SSRF guard: every hop is resolved and ALL addresses must be public. We connect to the validated IP itself
   (pinning), so DNS-rebinding cannot swap in an internal address after the check.
 * Only http/https on ports 80, 443, 8080, 8443. Max 6 redirects. 400 KB body cap. 10 s total deadline.
 * HTML is parsed with a tolerant stdlib parser; no JavaScript is ever run, no cookies are sent or kept.
 * The destination sees OUR server's IP, never the user's.
"""
import http.client
import ipaddress
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from urllib.parse import quote, urljoin, urlparse

import reputation
from analyzer import BRANDS, SHORTENERS, _registrable, analyze_url, verdict

MAX_BYTES, MAX_HOPS, TOTAL_TIMEOUT = 400_000, 6, 10.0
ALLOWED_PORTS = {80, 443, 8080, 8443}
UA = ("Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/124.0 Mobile Safari/537.36")
SENSITIVE_RE = re.compile(r"\b(otp|cvv|cvc|mpin|aadhaar|aadhar|upi|ifsc|ssn|netbanking|passcode|card.?(?:number|no)|credit.?card|cc-number|pan.?(?:card|number|no)|account.?(?:no|number)|atm.?pin)\b|one.?time.?(?:pass|code)", re.I)
# invisible frames that nearly every legitimate site has (analytics / tag managers / ad pixels)
BENIGN_FRAME_RE = re.compile(r"googletagmanager\.com|google-analytics\.com|doubleclick\.net|facebook\.com/tr|connect\.facebook\.net|hotjar\.com|clarity\.ms|youtube(?:-nocookie)?\.com|google\.com/recaptcha|recaptcha\.net|hcaptcha\.com|bing\.com|linkedin\.com|twitter\.com|snapchat\.com|adsrvr\.org|criteo\.", re.I)
LOGIN_TITLE_RE = re.compile(r"\b(sign.?in|log.?in|verify|verification|secure|update|confirm|password|banking|netbanking|wallet|account)\b", re.I)
EXFIL_RE = re.compile(r"api\.telegram\.org/bot|discord(?:app)?\.com/api/webhooks|formspree\.io|web3forms\.com|getform\.io|formsubmit\.co", re.I)
OBFUSCATION_RE = re.compile(r"eval\s*\(\s*(?:atob|unescape|decodeURIComponent)|document\.write\s*\(\s*unescape|String\.fromCharCode\s*\((?:\s*\d+\s*,){12,}|\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){25,}", re.I)


class FetchError(Exception):
    pass


# ------------------------------------------------------------------ network
def _host_ascii(host: str) -> str:
    try:
        return host.encode("idna").decode()
    except UnicodeError:
        raise FetchError("invalid domain name")


def _resolve(host: str, port: int, allow_private: bool) -> str:
    try:
        infos = socket.getaddrinfo(_host_ascii(host), port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise FetchError("domain does not resolve (it may already be taken down)")
    ips = [i[4][0].split("%")[0] for i in infos]
    if not ips:
        raise FetchError("domain does not resolve")
    if not allow_private and not all(ipaddress.ip_address(ip).is_global for ip in ips):
        raise FetchError("blocked: address is private/internal")
    ips.sort(key=lambda ip: ":" in ip)  # prefer IPv4
    return ips[0]


def _get(url: str, deadline: float, allow_private: bool):
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise FetchError("not a web address")
    https = p.scheme == "https"
    port = p.port or (443 if https else 80)
    if port not in ALLOWED_PORTS and not allow_private:
        raise FetchError(f"unusual port {port} not fetched")
    ip = _resolve(p.hostname, port, allow_private)
    host = _host_ascii(p.hostname)

    def left():
        r = deadline - time.monotonic()
        if r <= 0:
            raise FetchError("timed out")
        return r

    sock = socket.create_connection((ip, port), timeout=min(4.0, left()))
    try:
        if https:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # phishing sites often have bad certs; we only read
            sock = ctx.wrap_socket(sock, server_hostname=host)
        path = quote(p.path or "/", safe="/:@!$&'()*+,;=-._~%") + (("?" + quote(p.query, safe="=&%+:/,;@!$'()*-._~")) if p.query else "")
        hostline = host if port in (80, 443) else f"{host}:{port}"
        sock.settimeout(min(5.0, left()))
        sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {hostline}\r\nUser-Agent: {UA}\r\n"
                      "Accept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.5\r\nAccept-Language: en-US,en;q=0.8\r\n"
                      "Accept-Encoding: identity\r\nConnection: close\r\n\r\n").encode("ascii", "ignore"))
        resp = http.client.HTTPResponse(sock, method="GET")
        resp.begin()
        body, truncated = b"", False
        while True:
            sock.settimeout(min(5.0, left()))
            chunk = resp.read1(8192)  # read1 returns what's available; read(n) would block until n bytes (slow-drip attack)
            if not chunk:
                break
            body += chunk
            if len(body) > MAX_BYTES:
                body, truncated = body[:MAX_BYTES], True
                break
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, body, truncated
    finally:
        sock.close()


# ------------------------------------------------------------------ HTML scan
class PageScan(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self.text, self.scripts = "", "", ""
        self.forms, self.inputs, self.iframes, self.script_srcs = [], [], [], []
        self.meta_refresh, self.blocks_interaction = None, False
        self._form, self._in_title, self._in_script, self._in_style, self._noscript = None, False, False, False, 0

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if any(k in a and "return false" in a[k].replace(" ", "").lower() for k in ("oncontextmenu", "onpaste", "oncopy")):
            self.blocks_interaction = True
        if tag == "noscript":
            self._noscript += 1
        if tag == "title":
            self._in_title = True
        elif tag == "style":
            self._in_style = True
        elif tag == "script":
            self._in_script = True
            if a.get("src"):
                self.script_srcs.append(a["src"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select"):
            t = (a.get("type") or "text").lower()
            meta = " ".join(a.get(k, "") for k in ("name", "id", "placeholder", "autocomplete", "aria-label"))
            item = {"type": t, "meta": meta}
            self.inputs.append(item)
            if self._form is not None:
                self._form["inputs"].append(item)
        elif tag == "iframe" and not self._noscript:
            style = a.get("style", "").replace(" ", "").lower()
            hidden = a.get("width") in ("0", "1") or a.get("height") in ("0", "1") or "display:none" in style or "visibility:hidden" in style
            self.iframes.append({"src": a.get("src", ""), "hidden": hidden})
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", a.get("content", ""), re.I)
            if m:
                self.meta_refresh = m.group(1).strip()

    def handle_endtag(self, tag):
        if tag == "noscript" and self._noscript:
            self._noscript -= 1
        if tag == "title":
            self._in_title = False
        elif tag == "style":
            self._in_style = False
        elif tag == "script":
            self._in_script = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif self._in_script:
            if len(self.scripts) < 60_000:
                self.scripts += data
        elif not self._in_style and len(self.text) < 20_000:
            self.text += " " + data


def _reg_of(url: str) -> str:
    try:
        return _registrable((urlparse(url).hostname or ""))
    except ValueError:
        return ""


def page_findings(scan: PageScan, final_url: str) -> list:
    out = []

    def add(level, title, detail, pts):
        out.append({"level": level, "title": title, "detail": detail, "points": pts})

    final_reg = _reg_of(final_url)
    pw = any(i["type"] == "password" for i in scan.inputs)
    sensitive = [i for i in scan.inputs if SENSITIVE_RE.search(i["meta"])]
    harvest = pw or bool(sensitive)

    if pw:
        add("low", "Page asks for a password", "Normal on real login pages, so it only matters together with the other signs here.", 6)
    if sensitive:
        what = sorted({m.group(0).upper() for i in sensitive for m in [SENSITIVE_RE.search(i["meta"])] if m})[:4]
        add("medium", "Page asks for OTP / card / ID details", f"Fields detected: {', '.join(what)}. Real services never ask for these on a page opened from a message.", 16)

    # where does the form send data?
    for f in scan.forms:
        action = urljoin(final_url, f["action"]) if f["action"] else final_url
        has_secret = any(i["type"] == "password" or SENSITIVE_RE.search(i["meta"]) for i in f["inputs"])
        if EXFIL_RE.search(action):
            add("high", "Form sends data to Telegram/Discord/form service", "Stolen details are delivered straight to the scammer’s chat. Legitimate sites never do this.", 40)
            break
        if has_secret and _reg_of(action) and _reg_of(action) != final_reg:
            add("high", "Login form posts to a different website", f"Typed details would be sent to {urlparse(action).hostname}, not to this site.", 32)
            break
        if has_secret and action.startswith("http://"):
            add("medium", "Form sends secrets without encryption", "The form submits over plain HTTP.", 14)
            break
    if EXFIL_RE.search(scan.scripts) and not any(f["title"].startswith("Form sends") for f in out):
        add("high", "Script sends data to Telegram/Discord", "A script on the page posts to a chat webhook, a common phishing-kit trick.", 36)

    # impersonation, only judged when the page is harvesting credentials
    if harvest:
        hay = (scan.title + " " + scan.text[:6000]).lower()
        title = scan.title.lower()
        for brand, legit in BRANDS.items():
            if final_reg in legit:
                continue
            pat = rf"\b{re.escape(brand)}\b"
            if re.search(pat, title) or (pw and len(re.findall(pat, hay)) >= 3):
                add("high", f"Page pretends to be {brand.title()}", f"It mentions {brand.title()} and asks for sensitive details, but the site is {final_reg or 'unrelated'}, not {legit[0]}.", 30)
                break

    # Short page title that names a brand on an unrelated site ("Microsoft page", "PayPal Login", "HDFC NetBanking").
    # Catches kits whose login is drawn by JavaScript (we never run JS, so there is no <form> to see).
    # Long titles are ignored on purpose: blogs and news articles mention brands all the time.
    title = scan.title.strip()
    if title and len(title.split()) <= 5 and not any(f["title"].startswith("Page pretends") for f in out):
        tl = title.lower()
        loginish = bool(LOGIN_TITLE_RE.search(tl))
        bare_page = len(scan.text.split()) < 40
        for brand, legit in BRANDS.items():
            if final_reg in legit or not re.search(rf"\b{re.escape(brand)}\b", tl):
                continue
            if loginish or ((scan.forms or bare_page) and bare_page):
                add("high" if loginish else "medium", f"Page title names {brand.title()} but the site isn’t {brand.title()}",
                    f"The page is titled “{title[:60]}” yet it is hosted on {final_reg or 'an unrelated site'}, not {legit[0]}.", 24 if loginish else 18)
                break

    odd_frames = [i for i in scan.iframes if i["hidden"] and not BENIGN_FRAME_RE.search(i["src"]) and _reg_of(urljoin(final_url, i["src"])) not in ("", final_reg)]
    if odd_frames:
        add("medium" if harvest else "low", "Hidden iframe from another site", "An invisible frame loads content from an unfamiliar website.", 12 if harvest else 4)
    if OBFUSCATION_RE.search(scan.scripts):
        add("medium", "Obfuscated script", "The page hides its code (eval/atob/escape chains) so reviewers can’t read it.", 14)
    if scan.blocks_interaction:
        add("low", "Blocks right-click / paste", "Phishing kits often disable these to stop victims inspecting or pasting.", 6)
    if scan.meta_refresh and _reg_of(urljoin(final_url, scan.meta_refresh)) not in ("", final_reg):
        add("medium", "Page silently redirects elsewhere", "A meta-refresh sends visitors to another website.", 14)
    if harvest and len(scan.text.split()) < 40:
        add("low", "Almost no real content", "A bare form with very little text is typical of a throwaway phishing page.", 6)
    return out


# ------------------------------------------------------------------ orchestration
def inspect_url(url: str, allow_private: bool = False) -> dict:
    """Follow redirects and scan the final page. Never raises; returns a JSON-safe summary + findings."""
    deadline = time.monotonic() + TOTAL_TIMEOUT
    chain, cur, scan, err = [], url, None, None
    for _ in range(MAX_HOPS + 1):
        try:
            status, headers, body, _trunc = _get(cur, deadline, allow_private)
        except FetchError as e:
            chain.append({"url": cur[:300], "status": None, "error": str(e)})
            err = str(e)
            break
        except (OSError, http.client.HTTPException, ssl.SSLError):
            chain.append({"url": cur[:300], "status": None, "error": "could not connect"})
            err = "could not connect (site down, or it blocks automated visitors)"
            break
        chain.append({"url": cur[:300], "status": status})
        loc = headers.get("location")
        if status in (301, 302, 303, 307, 308) and loc:
            nxt = urljoin(cur, loc)
            if urlparse(nxt).scheme not in ("http", "https"):
                err = "redirects to a non-web address"
                break
            cur = nxt
            continue
        if "html" in headers.get("content-type", "html").lower() or not headers.get("content-type"):
            scan = PageScan()
            try:
                scan.feed(body.decode("utf-8", "replace"))
            except Exception:
                pass
            if scan.meta_refresh and len(scan.text.split()) < 30 and len(chain) <= MAX_HOPS:  # bare page that just forwards
                nxt = urljoin(cur, scan.meta_refresh)
                if urlparse(nxt).scheme in ("http", "https"):
                    chain[-1]["via"] = "meta refresh"
                    cur, scan = nxt, None
                    continue
        break
    else:
        err = "too many redirects"

    final = chain[-1]["url"] if chain and chain[-1].get("status") else None
    findings = page_findings(scan, final) if (scan and final) else []
    if len(chain) >= 5 and not err:
        findings.append({"level": "medium", "title": "Long redirect chain", "detail": f"{len(chain) - 1} redirects before the real page: a way to dodge filters.", "points": 10})
    return {
        "fetched": bool(scan), "error": err, "chain": chain, "final_url": final,
        "title": re.sub(r"\s+", " ", scan.title).strip()[:120] if scan else "",
        "forms": len(scan.forms) if scan else 0, "has_password": any(i["type"] == "password" for i in scan.inputs) if scan else False,
        "findings": findings,
    }


def apply(r: dict, ins: dict) -> None:
    """Merge an inspection into a URL result (in place)."""
    findings = ins.pop("findings")
    r["inspection"] = ins

    def add(level, title, detail, pts):
        r["findings"].insert(0, {"level": level, "title": title, "detail": detail, "points": pts})
        r["score"] += pts

    final = ins.get("final_url")
    if final and _reg_of(final) != _reg_of(r["input"] if "://" in r["input"] else "http://" + r["input"]):
        r2 = analyze_url(final)
        reputation.enrich_url_result(r2, {})
        # The hostname ML model alone must not condemn a destination: count it only if rules/blocklists agree.
        ml_pts = sum(f["points"] for f in r2["findings"] if f["title"].startswith("AI model"))
        risk = r2["score"] if r2["score"] - ml_pts >= 25 else 0
        r["redirect"] = {"final_url": final, "verdict": r2["verdict"] if risk else "safe", "score": risk}
        host2 = urlparse(final).hostname
        if risk > r["score"]:
            add("high" if risk >= 55 else "medium", f"Redirects to a {'dangerous' if risk >= 55 else 'suspicious'} site",
                f"The link really goes to {host2}, which scores {risk}/100.", risk - r["score"])
        elif risk < 25 and r.get("host") in SHORTENERS:
            add("good", "Shortened link: destination looks safe", f"It leads to {host2}, which has no strong warning signs.", -18)
        else:
            add("low", "Redirects to a different site", f"The link ends at {host2}.", 0)
    for f in findings:
        add(f["level"], f["title"], f["detail"], f["points"])
    r["score"] = max(0, min(100, r["score"]))
    r["verdict"] = verdict(r["score"])


def run(result: dict, max_urls: int = 3, allow_private: bool = False) -> dict:
    """Inspect a URL result or every link (up to max_urls) in a message result, then re-score."""
    from analyzer import normalize_url, rescore_message
    targets = [result] if result["type"] == "url" else result.get("urls", [])[:max_urls]
    if not targets:
        return result
    with ThreadPoolExecutor(max_workers=3) as ex:
        futs = [ex.submit(inspect_url, normalize_url(t["input"]), allow_private) for t in targets]
        for t, f in zip(targets, futs):
            try:
                apply(t, f.result(timeout=TOTAL_TIMEOUT + 6))
            except Exception:
                t["inspection"] = {"fetched": False, "error": "inspection failed", "chain": [], "final_url": None, "title": "", "forms": 0, "has_password": False}
    if result["type"] == "message":
        rescore_message(result)
    return result
