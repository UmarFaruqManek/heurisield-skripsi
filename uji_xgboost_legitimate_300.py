r"""Prediksi offline 300 URL legitimate dengan model XGBoost 18 fitur beku.

Jalankan dari folder ini:
    python .\uji_xgboost_legitimate_300.py --dry-run
    python .\uji_xgboost_legitimate_300.py

Script ini tidak membuka situs atau menyesuaikan model/threshold.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from ekstrak_fitur_url import extract_url_features


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "persiapan_300_legitimate_xgboost" / "audit_300_terverifikasi.csv"
MODEL = ROOT / "hasil_perbandingan_6_model" / "model" / "XGBoost.joblib"
METRICS = ROOT / "hasil_perbandingan_6_model" / "evaluasi_model.json"
OUT = ROOT / "hasil_uji_xgboost_legitimate_300_baru"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    source = pd.read_csv(SOURCE)
    if len(source) != 300 or source.url.nunique() != 300:
        raise ValueError("Daftar uji harus berisi 300 URL unik")
    if source.domain_age_days.isna().any() or (source.domain_age_days < 0).any():
        raise ValueError("Ada umur domain kosong atau tidak valid")
    configuration = json.loads(METRICS.read_text(encoding="utf-8"))
    names = configuration["feature_names"]
    threshold = float(configuration["models"]["XGBoost"]["validation"]["threshold"])
    if len(names) != 18:
        raise ValueError("Kontrak model harus memuat 18 fitur")
    print(json.dumps({"rows": len(source), "unique_sites": source.site_key.nunique(),
                      "age_missing": int(source.domain_age_days.isna().sum()),
                      "features": len(names), "threshold": threshold,
                      "model": str(MODEL), "dry_run": args.dry_run},
                     ensure_ascii=False, indent=2))
    if args.dry_run:
        return
    if OUT.exists():
        raise FileExistsError(f"Tidak menimpa hasil uji sebelumnya: {OUT}")
    features = pd.DataFrame([extract_url_features(url) for url in source.url])
    features["domain_age_days"] = source.domain_age_days.to_numpy(dtype=float)
    model = joblib.load(MODEL)
    probability = np.asarray(model.predict_proba(features[names].to_numpy(dtype=float)))[:, 1]
    if not np.isfinite(probability).all():
        raise ValueError("Skor model tidak valid")
    predictions = np.where(probability >= threshold, "phishing", "legitimate")
    output = source[["url", "site_key", "domain_age_days", "checked_at_utc", "source_ror"]].copy()
    output.insert(1, "given_label", "legitimate")
    output["probability_phishing"] = probability
    output["predicted_label"] = predictions
    output["correct"] = predictions == "legitimate"
    OUT.mkdir()
    output.to_csv(OUT / "prediksi_per_url.csv", index=False, encoding="utf-8-sig")
    correct = int(output.correct.sum())
    summary = {"mode": "offline_url_only", "model": "XGBoost_18",
               "threshold": threshold, "total": len(output), "evaluated": len(output),
               "correct": correct, "incorrect": len(output) - correct,
               "legitimate_correct_percent": round(100 * correct / len(output), 2),
               "generated_at_utc": datetime.now(timezone.utc).isoformat(),
               "note": "Label halaman belum diverifikasi ulang dalam browser saat prediksi; tidak ada DOM atau brand."}
    (OUT / "ringkasan.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
