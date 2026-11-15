"""Builds data/dataset.csv (label,url,source) from free public sources.

phishing : Phishing.Database (ACTIVE links) + OpenPhish feed
benign   : Tranco top-sites list (research-grade ranking of popular domains)

Benign URLs are made realistic by mixing bare/www/other-subdomain hosts and homepages with sensitive-looking paths
(/login, /signin, /account ...) so the test measures false alarms on real login pages.
Honest limitation: benign paths are synthetic; real-world benign traffic is more varied.
"""
import csv
import io
import random
import sys
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from analyzer import _registrable  # noqa: E402

DATA = Path(__file__).resolve().parent.parent / "data"
DATA.mkdir(exist_ok=True)
N_PHISH, N_BENIGN, MAX_PER_DOMAIN = 20000, 20000, 3
random.seed(42)

SRC = {
    "phishdb": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "openphish": "https://openphish.com/feed.txt",
    "tranco": "https://tranco-list.eu/top-1m.csv.zip",
}
# Real users paste links like https://www.example.com or https://login.example.com, not only bare domains.
# (An earlier version used bare domains only, so the model learned "has www/subdomain => phishing" and flagged www.bbc.co.uk.)
SUBDOMAINS = ["m", "mobile", "login", "accounts", "my", "shop", "store", "blog", "support", "help", "mail", "app", "portal", "docs", "news", "en", "id", "www2"]
BENIGN_PATHS = ["", "", "", "/", "/login", "/signin", "/account", "/account/security", "/help/contact",
                "/products/12345", "/search?q=weather", "/verify-email", "/user/settings", "/secure/checkout"]


def get(url, name):
    cache = DATA / name
    if cache.exists():
        return cache.read_bytes()
    print("downloading", url)
    req = urllib.request.Request(url, headers={"User-Agent": "PhishGuard-eval/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r:
        b = r.read()
    cache.write_bytes(b)
    return b


def clean(u):
    u = u.strip()
    if not u or " " in u or len(u) > 300:
        return None
    if "://" not in u:
        u = "http://" + u
    try:
        h = urlparse(u).hostname
    except ValueError:
        return None
    return u if h and "." in h else None


def main():
    phish, per = [], {}
    for name, src in (("openphish", "openphish.txt"), ("phishdb", "phishdb.txt")):
        lines = get(SRC[name], src).decode("utf-8", "ignore").splitlines()
        random.shuffle(lines)
        for l in lines:
            u = clean(l)
            if not u:
                continue
            reg = _registrable(urlparse(u).hostname)
            if per.get(reg, 0) >= MAX_PER_DOMAIN:
                continue
            per[reg] = per.get(reg, 0) + 1
            phish.append((1, u, name))
            if len(phish) >= N_PHISH:
                break
        if len(phish) >= N_PHISH:
            break

    z = zipfile.ZipFile(io.BytesIO(get(SRC["tranco"], "tranco.zip")))
    rows = list(csv.reader(io.TextIOWrapper(z.open(z.namelist()[0]), "utf-8")))
    top = [r[1] for r in rows[:60000]]
    random.shuffle(top)
    phish_regs = set(per)
    benign = []
    for d in top:
        if _registrable(d) in phish_regs:  # a popular domain that also hosts phishing: skip to keep labels clean
            continue
        roll = random.random()
        host = d if roll < 0.40 else (f"www.{d}" if roll < 0.80 else f"{random.choice(SUBDOMAINS)}.{d}")
        benign.append((0, f"https://{host}{random.choice(BENIGN_PATHS)}", "tranco"))
        if len(benign) >= N_BENIGN:
            break

    out = DATA / "dataset.csv"
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["label", "url", "source"])
        w.writerows(phish + benign)
    print(f"wrote {out}: {len(phish)} phishing, {len(benign)} benign")


if __name__ == "__main__":
    main()
