"""Ablasi umur pada dua kandidat kuat dengan partisi data yang sama."""

import json
from pathlib import Path

import numpy as np
import pandas as pd

from latih_bandingkan_6_model import (
    DATA, FEATURES, RESULT, class_scores, choose_threshold, models,
)


def main() -> None:
    df = pd.read_csv(DATA)
    split = pd.read_csv(RESULT / "pembagian_data.csv")
    if not df.url.equals(split.url) or not df.label.equals(split.label):
        raise ValueError("Partisi tidak cocok dengan dataset")
    y = (df.label == "phishing").to_numpy(dtype=int)
    x = df[FEATURES[:-1]].to_numpy(dtype=float)
    indices = {name: np.flatnonzero(split.split.to_numpy() == name)
               for name in ("train", "validation", "test")}
    report = {"feature_count": len(FEATURES) - 1,
              "excluded": "domain_age_days", "models": {}}
    for name in ("HistGradientBoosting", "XGBoost", "ExtraTrees"):
        model = models()[name]
        model.fit(x[indices["train"]], y[indices["train"]])
        pv = model.predict_proba(x[indices["validation"]])[:, 1]
        threshold = choose_threshold(y[indices["validation"]], pv)
        pt = model.predict_proba(x[indices["test"]])[:, 1]
        report["models"][name] = {
            "validation": class_scores(y[indices["validation"]], pv, threshold),
            "test": class_scores(y[indices["test"]], pt, threshold),
        }
        print(name, report["models"][name]["test"], flush=True)
    (RESULT / "uji_tanpa_umur.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
