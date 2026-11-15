"""Measures PhishGuard detection accuracy on held-out data. Usage: python eval/evaluate.py [rules|ml|combined]"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, auc, load, metrics  # noqa: E402

from analyzer import analyze_url  # noqa: E402


def scorer(name):
    if name == "rules":
        return lambda u: analyze_url(u, live=False)["score"]
    import mlmodel
    if name == "ml":
        return lambda u: mlmodel.predict_score(u)
    return lambda u: analyze_url(u, live=False)["score"]  # combined: ML is part of analyze_url


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else "rules"
    test = load("test")
    y = [a for a, _ in test]
    f = scorer(name)
    scores = [f(u) for _, u in test]
    print(f"\n=== {name} | held-out test set: {sum(y)} phishing, {len(y) - sum(y)} benign ===")
    print(f"ROC-AUC: {auc(y, scores):.4f}")
    print(f"{'threshold':>10} {'detect%':>8} {'falsealarm%':>12} {'precision%':>11} {'F1':>6}")
    for thr in (15, 25, 40, 55, 70):
        m = metrics(y, scores, thr)
        print(f"{thr:>10} {m['tpr']*100:>8.1f} {m['fpr']*100:>12.2f} {m['precision']*100:>11.1f} {m['f1']:>6.3f}")

    fps = sorted((s, u) for (a, u), s in zip(test, scores) if not a and s >= 25)[::-1][:8]
    fns = [u for (a, u), s in zip(test, scores) if a and s < 25][:8]
    print("\nTop false alarms (safe sites flagged):"); [print(f"  {s:>3}  {u}") for s, u in fps]
    print("Sample missed phishing:"); [print("      ", u[:110]) for u in fns]


if __name__ == "__main__":
    main()
