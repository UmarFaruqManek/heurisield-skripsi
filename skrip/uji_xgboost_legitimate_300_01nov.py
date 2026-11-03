"""Uji URL saja pada 300 legitimate baru dengan model XGBoost 18 fitur beku."""

from __future__ import annotations

import csv
import hashlib
import json
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
import tldextract

from ekstrak_fitur_url import extract_url_features
from uji_xgboost_300_phishing_100_legitimate import lookup_age, registry_map


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "data/input_uji/kandidat_legitimate_baru_01nov" / "legitimate_fresh_300_subdomain_path_01nov.txt"
MODEL = ROOT / "hasil/hasil_perbandingan_6_model" / "model" / "XGBoost.joblib"
CONFIG = ROOT / "hasil/hasil_perbandingan_6_model" / "evaluasi_model.json"
SPLIT = ROOT / "hasil/hasil_perbandingan_6_model" / "pembagian_data.csv"
OUT = ROOT / "hasil/hasil_uji_xgboost_legitimate_300_01nov"
PUBLIC = tldextract.TLDExtract(suffix_list_urls=())
PRIVATE = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


def key(url: str, parser) -> str:
    host = urlsplit(url).hostname or ""
    return parser(host).top_domain_under_public_suffix or host


def main():
    urls = [line.strip() for line in SOURCE.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(urls) != 300 or len(set(urls)) != 300:
        raise ValueError("Input harus berisi 300 URL unik")
    model_config = json.loads(CONFIG.read_text(encoding="utf-8"))
    names = model_config["feature_names"]
    threshold = float(model_config["models"]["XGBoost"]["validation"]["threshold"])
    if len(names) != 18 or names[-1] != "domain_age_days" or threshold != 0.38:
        raise ValueError("Kontrak fitur/threshold berbeda dari model beku")
    split = pd.read_csv(SPLIT, usecols=["url", "site_key"])
    model_urls = set(split.url)
    model_sites = set(split.site_key)
    if any(url in model_urls or key(url, PRIVATE) in model_sites for url in urls):
        raise ValueError("Ada tumpang tindih URL atau domain dengan data model")

    OUT.mkdir(exist_ok=True)
    cache_path = OUT / "umur_domain_rdap.jsonl"
    cache = {}
    if cache_path.exists():
        for line in cache_path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
                cache[row["domain"]] = row
            except (ValueError, KeyError):
                continue
    domains = [key(url, PUBLIC) for url in urls]
    pending = sorted(set(domains) - set(cache))
    print(f"Memeriksa umur {len(pending)} domain publik melalui RDAP; checkpoint aktif.", flush=True)
    if pending:
        servers = registry_map()
        with cache_path.open("a", encoding="utf-8") as handle, ThreadPoolExecutor(max_workers=4) as pool:
            futures = {}
            for domain in pending:
                futures[pool.submit(lookup_age, domain, servers)] = domain
                time.sleep(0.20)
            for i, future in enumerate(as_completed(futures), 1):
                row = future.result()
                cache[row["domain"]] = row
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
                handle.flush()
                if i % 50 == 0 or i == len(pending):
                    found = sum(value.get("status") == "found" for value in cache.values())
                    print(f"Umur {i}/{len(pending)}; ditemukan={found}", flush=True)

    features = pd.DataFrame([extract_url_features(url) for url in urls])
    ages = np.array([cache.get(domain, {}).get("age_days", np.nan) for domain in domains], dtype=float)
    valid = np.isfinite(ages) & (ages >= 0)
    probabilities = np.full(len(urls), np.nan)
    if valid.any():
        features.loc[valid, "domain_age_days"] = ages[valid]
        model = joblib.load(MODEL)
        probabilities[valid] = model.predict_proba(features.loc[valid, names].to_numpy(dtype=float))[:, 1]
    rows = []
    for i, url in enumerate(urls):
        prediction = "phishing" if probabilities[i] >= threshold else "legitimate" if valid[i] else "no_analysis"
        rows.append({"url": url, "actual_label": "legitimate", "public_domain": domains[i],
                     "site_key": key(url, PRIVATE), "domain_age_days": int(ages[i]) if valid[i] else "",
                     "age_status": cache.get(domains[i], {}).get("status", "not_checked"),
                     "probability_phishing": round(float(probabilities[i]), 6) if valid[i] else "",
                     "prediction": prediction,
                     "correct": prediction == "legitimate" if valid[i] else ""})
    with (OUT / "prediksi_per_url.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    evaluated = int(valid.sum())
    correct = sum(row["prediction"] == "legitimate" for row in rows)
    summary = {"mode": "offline_url_only", "model": "XGBoost_18", "threshold": threshold,
               "total": len(urls), "evaluated": evaluated, "correct": correct,
               "incorrect": evaluated - correct, "no_analysis": len(urls) - evaluated,
               "coverage_percent": round(100 * evaluated / len(urls), 2),
               "accuracy_on_evaluated_percent": round(100 * correct / evaluated, 2) if evaluated else None,
               "age_status": dict(Counter(row["age_status"] for row in rows)),
               "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
               "model_sha256": hashlib.sha256(MODEL.read_bytes()).hexdigest(),
               "generated_at_utc": datetime.now(timezone.utc).isoformat(),
               "note": "Prediksi menggunakan teks URL awal dan umur domain dari RDAP, API cadangan, atau WHOIS registri. Tidak membuka halaman untuk DOM/brand dan tidak memverifikasi label halaman saat prediksi."}
    (OUT / "ringkasan.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
