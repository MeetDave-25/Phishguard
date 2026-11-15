import csv
import hashlib
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from analyzer import _registrable  # noqa: E402


def load(split: str):
    """split = 'train' | 'test'. Split is by registrable domain (hash), so no domain appears in both."""
    rows = []
    with open(ROOT / "data" / "dataset.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            reg = _registrable(urlparse(r["url"]).hostname or "")
            in_test = int(hashlib.md5(reg.encode()).hexdigest(), 16) % 5 == 0
            if (split == "test") == in_test:
                rows.append((int(r["label"]), r["url"]))
    return rows


def metrics(y, scores, thr):
    tp = sum(1 for a, s in zip(y, scores) if a and s >= thr)
    fn = sum(1 for a, s in zip(y, scores) if a and s < thr)
    fp = sum(1 for a, s in zip(y, scores) if not a and s >= thr)
    tn = sum(1 for a, s in zip(y, scores) if not a and s < thr)
    tpr = tp / (tp + fn) if tp + fn else 0
    fpr = fp / (fp + tn) if fp + tn else 0
    prec = tp / (tp + fp) if tp + fp else 0
    f1 = 2 * prec * tpr / (prec + tpr) if prec + tpr else 0
    return dict(thr=thr, tpr=tpr, fpr=fpr, precision=prec, f1=f1, tp=tp, fp=fp, tn=tn, fn=fn)


def auc(y, scores):
    pos = [s for a, s in zip(y, scores) if a]
    neg = sorted(s for a, s in zip(y, scores) if not a)
    import bisect
    total = 0.0
    for p in pos:
        lo, hi = bisect.bisect_left(neg, p), bisect.bisect_right(neg, p)
        total += lo + 0.5 * (hi - lo)
    return total / (len(pos) * len(neg)) if pos and neg else 0
