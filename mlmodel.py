"""Small, fast, offline ML model that scores how much a URL's HOSTNAME resembles known phishing hosts.

Trained by eval/train.py on public data (Phishing.Database/OpenPhish vs Tranco top sites).
Hostname-only on purpose: benign test paths are synthetic, so path features would inflate accuracy dishonestly.
"""
import math
import os
import re
import threading
from pathlib import Path
from urllib.parse import urlparse

import numpy as np

MODEL_PATH = Path(__file__).resolve().parent / "models" / "url_model.joblib"
_model = None
_checked = False
_lock = threading.Lock()


def _host(url: str) -> str:
    if "://" not in url:
        url = "http://" + url
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def host_texts(urls):
    # '^' and '$' mark host start/end so n-grams can learn prefixes/suffixes like '.netlify.app$'
    return ["^" + _host(u) + "$" for u in urls]


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def num_features(urls):
    rows = []
    for u in urls:
        h = _host(u)
        parts = h.split(".")
        label = parts[-2] if len(parts) >= 2 else h
        rows.append([
            len(h), len(parts), h.count("-"), sum(c.isdigit() for c in h) / max(len(h), 1),
            _entropy(label), float("xn--" in h), len(label), float(bool(re.fullmatch(r"[\d.]+", h))),
            max((len(p) for p in parts), default=0),
        ])
    return np.array(rows, dtype=float)


def build_pipeline():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import FeatureUnion, Pipeline
    from sklearn.preprocessing import FunctionTransformer, StandardScaler
    feats = FeatureUnion([
        ("ngrams", Pipeline([("t", FunctionTransformer(host_texts)),
                             ("v", TfidfVectorizer(analyzer="char", ngram_range=(2, 5), min_df=3, max_features=250000, sublinear_tf=True, lowercase=False))])),
        ("nums", Pipeline([("t", FunctionTransformer(num_features)), ("s", StandardScaler())])),
    ])
    return Pipeline([("f", feats), ("clf", LogisticRegression(C=4.0, max_iter=2000))])


def _load():
    """Thread-safe lazy load. (A previous version flagged 'checked' before loading finished, so concurrent
    first requests silently skipped the model and scored without it.)"""
    global _model, _checked
    if _checked:
        return _model
    with _lock:
        if _checked:
            return _model
        if not os.getenv("PHISHGUARD_NO_ML"):  # used by eval to measure the rules-only baseline
            try:
                import joblib
                _model = joblib.load(MODEL_PATH)
            except Exception:
                _model = None
        _checked = True  # set only AFTER loading finished
        return _model


def available() -> bool:
    return _load() is not None


def predict_proba(url: str):
    """Probability (0-1) that the hostname looks like phishing, or None if no model is installed."""
    m = _load()
    return None if m is None else float(m.predict_proba([url])[0][1])


def predict_score(url: str) -> int:
    p = predict_proba(url)
    return 0 if p is None else round(p * 100)
