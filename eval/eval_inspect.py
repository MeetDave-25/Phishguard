"""Does page inspection improve detection? Samples held-out URLs, scores each BEFORE and AFTER inspection.

Usage: python eval/eval_inspect.py [N_PER_CLASS=150]
NOTE: this makes read-only GET requests to live phishing sites (no JS run, no cookies). Phishing pages die fast,
so many will already be gone: the 'fetched' rate is reported and the gain applies only to pages still alive.
"""
import copy
import random
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import load, metrics  # noqa: E402

import inspector  # noqa: E402
from analyzer import analyze_url, normalize_url  # noqa: E402


def one(url):
    base = analyze_url(url)
    ins = inspector.inspect_url(normalize_url(url))
    after = copy.deepcopy(base)
    page_titles = [f["title"] for f in ins["findings"]]
    fetched = ins["fetched"]
    inspector.apply(after, ins)
    return base["score"], after["score"], fetched, page_titles, ins.get("error")


def main():
    n = int(next((a for a in sys.argv[1:] if a.isdigit()), 150))
    random.seed(7)
    test = load("test")
    if "--unseen" in sys.argv:  # phishing from domains the shipped model was NOT trained on (no leakage)
        import csv
        from urllib.parse import urlparse
        from analyzer import _registrable
        root = Path(__file__).resolve().parent.parent / "data"
        with open(root / "dataset.csv", encoding="utf-8") as f:
            seen = {_registrable(urlparse(r["url"]).hostname or "") for r in csv.DictReader(f) if r["label"] == "1"}
        pool = [l.strip() for l in (root / "phishdb.txt").read_text("utf-8", "ignore").splitlines() if l.strip()]
        random.shuffle(pool)
        phish, per = [], {}
        for u in pool:
            if "://" not in u:
                u = "http://" + u
            try:
                reg = _registrable(urlparse(u).hostname or "")
            except ValueError:
                continue
            if not reg or reg in seen or per.get(reg, 0) >= 1:
                continue
            per[reg] = 1
            phish.append(u)
            if len(phish) >= n:
                break
        print(f"using {len(phish)} phishing URLs from domains the model has never seen (NOT fresh: most are already dead)")
    else:
        phish = random.sample([u for a, u in test if a], n)
    benign = random.sample([u for a, u in test if not a], n)
    items = [(1, u) for u in phish] + [(0, u) for u in benign]
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=12) as ex:
        res = list(ex.map(lambda it: one(it[1]), items))
    y = [a for a, _ in items]
    before, after = [r[0] for r in res], [r[1] for r in res]
    print(f"\n{n} phishing + {n} safe URLs, {time.time() - t0:.0f}s")
    for label, cls in (("phishing", 1), ("safe", 0)):
        rs = [r for (a, _), r in zip(items, res) if a == cls]
        print(f"  {label}: page fetched for {sum(r[2] for r in rs)}/{len(rs)}")
    for label, cls in (("phishing", 1), ("safe", 0)):
        errs = Counter((r[4] or "(no error, but no HTML page)")[:45] for (a, _), r in zip(items, res) if a == cls and not r[2])
        print(f"  why {label} pages weren't inspected:", dict(errs.most_common(4)))
    print(f"\n{'':>10} {'detect%':>8} {'falsealarm%':>12}   (before -> after inspection)")
    for thr in (25, 55):
        b, a = metrics(y, before, thr), metrics(y, after, thr)
        print(f"  score>={thr}: detect {b['tpr']*100:5.1f}% -> {a['tpr']*100:5.1f}%    false alarms {b['fpr']*100:5.2f}% -> {a['fpr']*100:5.2f}%")
    missed = [r for (a, _), r in zip(items, res) if a == 1 and r[2] and r[0] < 25]
    print(f"\n  alive phishing pages that the URL checks MISSED (score<25): {len(missed)}"
          f" -> inspection rescues {sum(r[1] >= 25 for r in missed)} of them")
    alive = [(r, a) for (a, _), r in zip(items, res) if a == 1 and r[2]]
    if alive:
        for thr in (25, 55):
            b = sum(r[0] >= thr for r, _ in alive) / len(alive) * 100
            a = sum(r[1] >= thr for r, _ in alive) / len(alive) * 100
            print(f"  on phishing pages still ALIVE ({len(alive)}), score>={thr}: {b:.0f}% -> {a:.0f}%")
    tc = Counter(t for (a, _), r in zip(items, res) if a == 1 for t in r[3])
    print("\nTop page signals on phishing:", tc.most_common(6))
    fc = Counter(t for (a, _), r in zip(items, res) if a == 0 for t in r[3])
    print("Page signals on SAFE sites (false-alarm sources):", fc.most_common(6))


if __name__ == "__main__":
    main()
