r"""Hitung pengaruh 18 fitur XGBoost dari partisi uji internal yang dibekukan.

Gain menunjukkan bagian total gain split; kontribusi kelas memakai kontribusi
logit XGBoost (Tree SHAP) yang mendukung label aktual pada tiap kelompok.
Keduanya bukan persentase sebab-akibat atau probabilitas label.
"""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb

from latih_bandingkan_6_model import FEATURES


ROOT = Path(__file__).resolve().parents[1]
RESULT = ROOT / "hasil/hasil_perbandingan_6_model"
OUTPUT = ROOT / "hasil/audit_pengaruh_18_fitur_xgboost"
OUTPUT.mkdir(exist_ok=True)


def main():
    data = pd.read_csv(ROOT / "data/dataset/DATA_URL_18_FITUR.csv")
    split = pd.read_csv(RESULT / "pembagian_data.csv")
    if not data.url.equals(split.url) or not data.label.equals(split.label):
        raise ValueError("Partisi dan data tidak sejajar")
    test = split.split.eq("test")
    x = data.loc[test, FEATURES].to_numpy(dtype=float)
    y = data.loc[test, "label"].to_numpy()
    model = joblib.load(RESULT / "model" / "XGBoost.joblib")
    contributions = model.get_booster().predict(
        xgb.DMatrix(x, feature_names=FEATURES), pred_contribs=True
    )
    scores = model.predict_proba(x)[:, 1]
    reconstructed = 1 / (1 + np.exp(-contributions.sum(axis=1)))
    if not np.allclose(scores, reconstructed, atol=1e-5):
        raise AssertionError("Kontribusi tidak merekonstruksi skor model")
    core = contributions[:, :-1]
    phish_support = np.clip(core[y == "phishing"], 0, None).sum(axis=0)
    legit_support = np.clip(-core[y == "legitimate"], 0, None).sum(axis=0)
    gain = np.asarray(model.feature_importances_, dtype=float)
    if not np.isclose(gain.sum(), 1.0):
        gain = gain / gain.sum()
    table = pd.DataFrame({
        "fitur": FEATURES,
        "gain_global_persen": 100 * gain,
        "kontribusi_ke_legitimate_persen": 100 * legit_support / legit_support.sum(),
        "kontribusi_ke_phishing_persen": 100 * phish_support / phish_support.sum(),
        "rerata_arah_logit_legitimate": core[y == "legitimate"].mean(axis=0),
        "rerata_arah_logit_phishing": core[y == "phishing"].mean(axis=0),
        "median_legitimate": data.loc[test & data.label.eq("legitimate"), FEATURES].median().to_numpy(),
        "median_phishing": data.loc[test & data.label.eq("phishing"), FEATURES].median().to_numpy(),
    }).sort_values("gain_global_persen", ascending=False)
    table.to_csv(OUTPUT / "pengaruh_fitur_18.csv", index=False, encoding="utf-8-sig", float_format="%.6f")

    counts = {
        "dataset_rows": len(data),
        "test_rows": int(test.sum()),
        "test_legitimate": int((y == "legitimate").sum()),
        "test_phishing": int((y == "phishing").sum()),
        "age_missing": int(data.domain_age_days.isna().sum()),
        "http_by_label": data.assign(http=data.has_https_scheme.eq(0)).groupby("label").http.sum().astype(int).to_dict(),
        "has_ip_host_by_label": data.groupby("label").has_ip_host.sum().astype(int).to_dict(),
        "age_median_by_label": data.groupby("label").domain_age_days.median().to_dict(),
        "pages_dev_by_label": data[data.url.str.contains("pages.dev", regex=False)].label.value_counts().to_dict(),
        "gain_sum": round(float(table.gain_global_persen.sum()), 6),
        "legitimate_support_sum": round(float(table.kontribusi_ke_legitimate_persen.sum()), 6),
        "phishing_support_sum": round(float(table.kontribusi_ke_phishing_persen.sum()), 6),
    }
    (OUTPUT / "audit_ringkas.json").write_text(json.dumps(counts, ensure_ascii=False, indent=2), encoding="utf-8")
    print(table[["fitur", "gain_global_persen", "kontribusi_ke_legitimate_persen",
                 "kontribusi_ke_phishing_persen"]].round(2).to_string(index=False))
    print(json.dumps(counts, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
