"""Train the hostname model. Usage: python eval/train.py [--final]

Default: train on the train split, report on the held-out test split (honest numbers), save model.
--final: retrain on ALL data before saving (ship this one; the held-out numbers above still describe its quality).
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, auc, load, metrics  # noqa: E402

import joblib  # noqa: E402

import mlmodel  # noqa: E402


def main():
    final = "--final" in sys.argv
    train, test = load("train"), load("test")
    Xtr, ytr = [u for _, u in train], [a for a, _ in train]
    Xte, yte = [u for _, u in test], [a for a, _ in test]
    print(f"train {len(Xtr)} (phish {sum(ytr)}), test {len(Xte)} (phish {sum(yte)})")

    t = time.time()
    pipe = mlmodel.build_pipeline().fit(Xtr, ytr)
    print(f"trained in {time.time() - t:.1f}s")
    p = pipe.predict_proba(Xte)[:, 1]
    print(f"HELD-OUT ROC-AUC: {auc(yte, p):.4f}")
    for thr in (0.3, 0.5, 0.7, 0.9):
        m = metrics(yte, p, thr)
        print(f"  p>={thr}: detect {m['tpr']*100:5.1f}%  false-alarm {m['fpr']*100:5.2f}%  precision {m['precision']*100:5.1f}%")

    if final:
        pipe = mlmodel.build_pipeline().fit(Xtr + Xte, ytr + yte)
        print("retrained on all data")
    out = ROOT / "models"
    out.mkdir(exist_ok=True)
    joblib.dump(pipe, out / "url_model.joblib", compress=3)
    print("saved", out / "url_model.joblib", f"({(out / 'url_model.joblib').stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
