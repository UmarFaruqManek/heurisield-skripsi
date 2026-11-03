"""Uji offline XGBoost 18 fitur (umur terverifikasi) dan pembanding URL saja.

Ini memprediksi teks URL, bukan mengunjungi halaman atau menguji extension.
Umur domain dicari dari RDAP registri dengan checkpoint; URL tanpa umur tidak
dimasukkan ke metrik model 18 fitur. Semua URL tetap dinilai oleh model 17 fitur.
"""

from __future__ import annotations

import csv
import json
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import joblib
import numpy as np
import pandas as pd
import requests
import tldextract

from ekstrak_fitur_url import URL_FEATURES, extract_url_features
from latih_bandingkan_6_model import FEATURES, class_scores, choose_threshold, models


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "hasil/hasil_uji_xgboost_300_phishing_100_legitimate"
PHISH_SOURCE = Path(r"C:\Users\USER\.codex\attachments\089c9839-04e2-4f61-a152-ce8498c17c17\Pasted text.txt")
LEGIT_SOURCE = Path(r"C:\Users\USER\Downloads\legitimate_baru_100_uji_xgboost_31okt.txt")
PUBLIC = tldextract.TLDExtract(suffix_list_urls=())
PRIVATE = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "HeuriShield research evaluation/1.0", "Accept": "application/rdap+json, application/json"})


def read_urls(path):
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(lines) != len(set(lines)):
        raise ValueError(f"URL duplikat pada {path}")
    for url in lines:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError(f"URL tidak valid: {url}")
    return lines


def domain(url, parser):
    host = urlsplit(url).hostname or ""
    return parser(host).top_domain_under_public_suffix or host


def date_value(value):
    try:
        date = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return date.replace(tzinfo=timezone.utc) if date.tzinfo is None else date.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def registry_map():
    response = SESSION.get("https://data.iana.org/rdap/dns.json", timeout=15)
    response.raise_for_status()
    return {tld.lower(): servers[0] for tlds, servers in response.json()["services"]
            for tld in tlds if servers}


def lookup_age(domain_name, servers):
    suffix = PUBLIC(domain_name).suffix.lower().split(".")[-1]
    base = servers.get(suffix)
    if not base:
        return {"domain": domain_name, "status": "no_rdap_server"}
    try:
        response = SESSION.get(urljoin(base.rstrip("/") + "/", "domain/" + domain_name), timeout=12)
        if response.status_code != 200:
            return {"domain": domain_name, "status": "http_" + str(response.status_code)}
        payload = response.json()
        reported = str(payload.get("ldhName") or payload.get("unicodeName") or "").lower().rstrip(".")
        if reported and reported != domain_name:
            return {"domain": domain_name, "status": "domain_mismatch"}
        for event in payload.get("events", []):
            if event.get("eventAction", "").lower() == "registration":
                created = date_value(event.get("eventDate"))
                if created and created <= datetime.now(timezone.utc):
                    return {"domain": domain_name, "status": "found", "registered_at": created.isoformat(),
                            "age_days": (datetime.now(timezone.utc).date() - created.date()).days,
                            "provider": base}
        return {"domain": domain_name, "status": "no_registration_event"}
    except (requests.RequestException, ValueError, KeyError, TypeError) as exc:
        return {"domain": domain_name, "status": type(exc).__name__}


def load_age_cache():
    path = OUT / "rdap_age_cache.jsonl"
    cache = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                item = json.loads(line)
                cache[item["domain"]] = item
            except (ValueError, KeyError):
                continue
    return path, cache


def main():
    OUT.mkdir(exist_ok=True)
    phish, legit = read_urls(PHISH_SOURCE), read_urls(LEGIT_SOURCE)
    if len(phish) != 300 or len(legit) != 100:
        raise ValueError(f"Diharapkan 300 phishing dan 100 legitimate; diperoleh {len(phish)}, {len(legit)}")
    all_urls = phish + legit
    if len(all_urls) != len(set(all_urls)):
        raise ValueError("URL sama muncul pada kedua label")
    (OUT / "input_phishing_300.txt").write_text("\n".join(phish) + "\n", encoding="utf-8")
    (OUT / "input_legitimate_100.txt").write_text("\n".join(legit) + "\n", encoding="utf-8")

    split = pd.read_csv(ROOT / "hasil/hasil_perbandingan_6_model" / "pembagian_data.csv")
    train_sites = set(split.loc[split.split == "train", "site_key"])
    validation_sites = set(split.loc[split.split == "validation", "site_key"])
    test_sites = set(split.loc[split.split == "test", "site_key"])
    source_urls = set(split.url)
    print("Menghitung model URL saja pada semua URL...", flush=True)

    df = pd.read_csv(ROOT / "data/dataset/DATA_URL_18_FITUR.csv")
    if not df.url.equals(split.url) or not df.label.equals(split.label):
        raise ValueError("Dataset dan partisi model tidak cocok")
    y = (df.label == "phishing").to_numpy(dtype=int)
    train = np.flatnonzero(split.split.to_numpy() == "train")
    validation = np.flatnonzero(split.split.to_numpy() == "validation")
    x_train = df[list(URL_FEATURES)].to_numpy(dtype=float)
    model17 = models()["XGBoost"]
    model17.fit(x_train[train], y[train])
    val_probability = model17.predict_proba(x_train[validation])[:, 1]
    threshold17 = choose_threshold(y[validation], val_probability)
    joblib.dump(model17, OUT / "XGBoost_17_URL_tanpa_umur.joblib", compress=3)

    sites = [domain(url, PRIVATE) for url in all_urls]
    domains = [domain(url, PUBLIC) for url in all_urls]
    rows = [{"url": url, "given_label": "phishing" if i < len(phish) else "legitimate",
             "site_key": sites[i], "public_domain": domains[i],
             "in_training_site": int(sites[i] in train_sites),
             "in_validation_site": int(sites[i] in validation_sites),
             "in_test_site": int(sites[i] in test_sites),
             "exact_url_in_corpus": int(url in source_urls)}
            for i, url in enumerate(all_urls)]
    feat = pd.DataFrame([extract_url_features(url) for url in all_urls])
    prob17 = model17.predict_proba(feat[list(URL_FEATURES)].to_numpy(dtype=float))[:, 1]
    for i, row in enumerate(rows):
        row["XGB17_prob_phishing"] = round(float(prob17[i]), 6)
        row["XGB17_prediction"] = "phishing" if prob17[i] >= threshold17 else "legitimate"

    age_path, cache = load_age_cache()
    missing = sorted(set(domains) - set(cache))
    print(f"RDAP: {len(missing)} domain publik belum dicatat; maksimum 3 permintaan paralel.", flush=True)
    servers = registry_map()
    # Hanya RDAP resmi, tanpa API komersial yang cepat terkena pembatasan.
    with age_path.open("a", encoding="utf-8") as handle, ThreadPoolExecutor(max_workers=3) as pool:
        futures = {}
        for domain_name in missing:
            futures[pool.submit(lookup_age, domain_name, servers)] = domain_name
            time.sleep(0.35)
        for future in as_completed(futures):
            item = future.result()
            cache[item["domain"]] = item
            handle.write(json.dumps(item, ensure_ascii=False) + "\n")
            handle.flush()

    model18 = joblib.load(ROOT / "hasil/hasil_perbandingan_6_model" / "model" / "XGBoost.joblib")
    eval_report = json.loads((ROOT / "hasil/hasil_perbandingan_6_model" / "evaluasi_model.json").read_text(encoding="utf-8"))
    threshold18 = eval_report["models"]["XGBoost"]["validation"]["threshold"]
    age = np.array([cache.get(d, {}).get("age_days", np.nan) for d in domains], dtype=float)
    available = np.isfinite(age)
    for i, row in enumerate(rows):
        row["domain_age_days"] = int(age[i]) if available[i] else ""
        row["age_status"] = cache.get(domains[i], {}).get("status", "missing")
        row["XGB18_prob_phishing"] = ""
        row["XGB18_prediction"] = ""
    if available.any():
        x18 = feat.loc[available, list(URL_FEATURES)].copy()
        x18["domain_age_days"] = age[available]
        prob18 = model18.predict_proba(x18[FEATURES].to_numpy(dtype=float))[:, 1]
        for index, probability in zip(np.flatnonzero(available), prob18):
            rows[index]["XGB18_prob_phishing"] = round(float(probability), 6)
            rows[index]["XGB18_prediction"] = "phishing" if probability >= threshold18 else "legitimate"

    pd.DataFrame(rows).to_csv(OUT / "prediksi_per_url.csv", index=False, encoding="utf-8-sig")
    report = {"input": {"phishing": len(phish), "legitimate": len(legit)},
              "model17": {"features": 17, "threshold": threshold17},
              "model18": {"features": 18, "threshold": threshold18},
              "age_available": {label: sum(r["given_label"] == label and bool(r["domain_age_days"]) for r in rows)
                                for label in ("phishing", "legitimate")},
              "age_status": dict(Counter(row["age_status"] for row in rows)),
              "leakage": {label: {key: sum(r["given_label"] == label and r[key] for r in rows)
                                  for key in ("exact_url_in_corpus", "in_training_site", "in_validation_site", "in_test_site")}
                          for label in ("phishing", "legitimate")}}
    for name, threshold in (("XGB17", threshold17), ("XGB18", threshold18)):
        report[name] = {}
        for label in ("phishing", "legitimate"):
            subset = [r for r in rows if r["given_label"] == label and r[name + "_prediction"]]
            report[name][label] = {"evaluated": len(subset), "correct": sum(r[name + "_prediction"] == label for r in subset),
                                   "incorrect": sum(r[name + "_prediction"] != label for r in subset),
                                   "no_prediction": (len(phish) if label == "phishing" else len(legit)) - len(subset)}
    report["limitations"] = ["Offline: label dari daftar masukan belum diverifikasi terhadap halaman live.",
                             "XGB17 dilatih ulang tanpa umur; ini berbeda dari model XGB18 sebelumnya.",
                             "Metrik XGB18 hanya untuk URL yang berhasil memperoleh umur domain RDAP.",
                             "URL/domain yang tumpang tindih dengan data latih bukan uji eksternal independen."]
    (OUT / "ringkasan.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
