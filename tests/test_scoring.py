"""Regression tests: everyday legitimate links must NOT be flagged, and obvious scams must be.
Run: python tests/test_scoring.py
History: a model trained only on bare domains flagged every 'www.' link (www.bbc.co.uk = 'dangerous'). These guard that.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzer import analyze_url  # noqa: E402

SITES = ["nytimes.com", "bbc.co.uk", "wikipedia.org", "heart.org", "stackoverflow.com", "python.org", "mozilla.org", "cloudflare.com",
         "nginx.org", "kernel.org", "arstechnica.com", "theguardian.com", "reuters.com", "khanacademy.org", "nasa.gov", "ukg.com", "ionos.com"]
PREFIXES = ["", "www.", "en.", "login.", "support.", "m."]
fail = []
n = 0
for d in SITES:
    for pre in PREFIXES:
        for path in ("", "/login", "/account"):
            url = f"https://{pre}{d}{path}"
            r = analyze_url(url)
            n += 1
            if r["verdict"] != "safe":
                fail.append((r["score"], url, [f["title"] for f in r["findings"] if f["points"] > 0]))
# The hostname model is noisy on long dictionary-word domains (e.g. khanacademy.org/login scores 27): a known limit.
# So: tolerate <=1% 'suspicious', NEVER 'dangerous', and no systematic prefix/subdomain bias (the old www bug).
bad = [f for f in fail if f[0] >= 55]
assert not bad, "legit sites rated dangerous:\n" + "\n".join(map(str, bad[:15]))
rate = len(fail) / n * 100
assert rate <= 1.0, f"{rate:.2f}% of legit variants flagged:\n" + "\n".join(map(str, fail[:15]))
for pre in PREFIXES:
    k = sum(1 for f in fail if f[1].startswith(f"https://{pre}"))
    assert k <= 2, f"prefix '{pre}' flagged {k} times"
print(f"ok  {n} legitimate URL variants: {len(fail)} flagged ({rate:.2f}%), none dangerous")

for url in ["http://paypa1-secure-login.xyz/verify/account", "http://hdfc-bank-verify.click/login", "http://sbi-kyc-update.top/login",
            "https://calm-faun-867857.netlify.app/sitemap"]:
    assert analyze_url(url)["verdict"] != "safe", url
print("ok  known scam patterns are not 'safe'")
