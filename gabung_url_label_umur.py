"""Gabungkan URL berlabel dari sumber utama tanpa melatih model atau memanggil API.

Hasil utama tepat tiga kolom. Audit terpisah menjaga asal, status uji, dan konflik.
"""

from __future__ import annotations

import csv
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


csv.field_size_limit(sys.maxsize)
HERE = Path(__file__).resolve().parent
ROOT = Path(r"D:\mesin crawl")
DEPLOY = Path(r"D:\Deployment Extension")
EXPERIMENT = Path(r"D:\experimen")
DOWNLOADS = Path(r"C:\Users\USER\Downloads")

OUTPUT = HERE / "gabungan_url_label_umur.csv"
AUDIT = HERE / "audit_gabungan_url.csv"
CONFLICTS = HERE / "konflik_label_url.csv"
SUMMARY = HERE / "ringkasan_gabungan.json"

records: dict[str, dict] = {}
source_stats: dict[str, Counter] = defaultdict(Counter)


def normalize_url(value: str) -> tuple[str, str] | None:
    url = str(value or "").strip()
    if not url or any(ord(ch) < 32 for ch in url):
        return None
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower().rstrip(".")
        if scheme not in ("http", "https") or not host:
            return None
        port = parts.port
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        # Pertahankan userinfo dan fragmen: keduanya dapat memuat pola URL
        # yang perlu diekstraksi nanti, termasuk simbol @ dan rute SPA.
        userinfo = ""
        if parts.username is not None:
            userinfo = parts.username + (f":{parts.password}" if parts.password is not None else "") + "@"
        netloc = userinfo + host + (f":{port}" if port and port != (80 if scheme == "http" else 443) else "")
        canonical = urlunsplit((scheme, netloc, parts.path or "/", parts.query, parts.fragment))
        return canonical, url
    except ValueError:
        return None


def normalize_label(value: str) -> str | None:
    text = str(value or "").strip().lower()
    if text in ("legitimate", "benign", "good", "safe"):
        return "legitimate"
    if text in ("phishing", "phish", "bad", "dangerous"):
        return "phishing"
    return None


def usable_age(value, *, allowed=True):
    if not allowed or value is None or str(value).strip() == "":
        return None
    try:
        number = float(value)
        return round(number, 3) if math.isfinite(number) and 0 <= number <= 60000 else None
    except (ValueError, TypeError):
        return None


def add(source: str, group: str, url_value, label_value, age_value=None,
        *, age_rank=0, age_allowed=True, status=""):
    stats = source_stats[source]
    stats["read"] += 1
    parsed = normalize_url(url_value)
    label = normalize_label(label_value)
    if not parsed or not label:
        stats["invalid_or_unlabeled"] += 1
        return
    key, url = parsed
    age = usable_age(age_value, allowed=age_allowed)
    rec = records.setdefault(key, {"url": url, "labels": set(), "sources": set(),
                                   "groups": set(), "age": None, "age_rank": -1,
                                   "age_source": "", "status": set(), "rows": 0})
    rec["labels"].add(label)
    rec["sources"].add(source)
    rec["groups"].add(group)
    if status:
        rec["status"].add(status)
    rec["rows"] += 1
    if age is not None and age_rank > rec["age_rank"]:
        rec["age"] = age
        rec["age_rank"] = age_rank
        rec["age_source"] = source
    stats["accepted_rows"] += 1
    if age is not None:
        stats["rows_with_age"] += 1


def read_csv(path: Path, source: str, group: str, url_col: str, label_col: str,
             age_col: str | None = None, *, age_rank=0, label_map=None,
             age_allowed_fn=None, row_filter=None, status_col=None):
    if not path.is_file():
        source_stats[source]["missing_file"] += 1
        return
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames or url_col not in reader.fieldnames or label_col not in reader.fieldnames:
            source_stats[source]["missing_columns"] += 1
            return
        for row in reader:
            if row_filter and not row_filter(row):
                source_stats[source]["filtered"] += 1
                continue
            label = row.get(label_col, "")
            if label_map:
                label = label_map.get(str(label).strip(), "")
            add(source, group, row.get(url_col), label,
                row.get(age_col) if age_col else None,
                age_rank=age_rank,
                age_allowed=age_allowed_fn(row) if age_allowed_fn else True,
                status=row.get(status_col, "") if status_col else "")


def main():
    # Arsip mentah lama; file hasil 60 fitur tanpa URL tidak dapat dipakai sebagai sumber URL.
    read_csv(ROOT / r"_backup_root_cleanup_20261011\folders\ml_pipeline_v2_domain_age_recovered_v1\cleaned_master_success_v2_domain_age_recovered.csv",
             "master_lama", "pelatihan_lama", "original_url", "label", "original_domain_age_days", age_rank=2,
             age_allowed_fn=lambda r: bool(r.get("original_domain_creation_date")) or r.get("original_rdap_available") in ("1", "1.0", "True"))
    read_csv(ROOT / r"ml_pipeline_v2_domain_age_brand_recovered_118_v1\combined_full_recovered_118_source_rows.csv",
             "sumber_118_berurl", "pelatihan_lama", "original_url", "label", "original_domain_age_days", age_rank=2)
    read_csv(ROOT / r"Heurishield-V5\reports\new-legitimate-crawl-audit-v1\new_legitimate_success_records.csv",
             "crawl_legitimate_baru", "crawl_terdahulu", "original_url", "label", "original_domain_age_days", age_rank=2)
    read_csv(ROOT / r"LIVE_RETRAIN_RULEFIT60_CRAWL\live_eval_retrain_features_combined.csv",
             "live_retrain_60", "pelatihan_lama", "input_url", "label", "original_domain_age_days", age_rank=3)
    read_csv(DEPLOY / r"data\sumber\data_tambahan_live.csv",
             "live_train_60", "pelatihan_lama", "input_url", "label", "original_domain_age_days", age_rank=3)
    read_csv(EXPERIMENT / r"persiapan_model_v5_age_observed_only\dataset_32_fitur_umur_observed_only.csv",
             "eksperimen_32_observed", "pelatihan_eksperimen", "url", "label", "domain_age_days", age_rank=3,
             age_allowed_fn=lambda r: r.get("domain_age_value_source") == "source_observed" and r.get("domain_age_status") == "available")

    # Kumpulan eksternal yang label numeriknya diperiksa melalui berkas pemisahan
    # phishing/legitimate di Downloads. Ini bukan hasil verifikasi live saat ini.
    read_csv(DOWNLOADS / r"data\PhiUSIIL_Phishing_URL_Dataset.csv",
             "PhiUSIIL", "dataset_eksternal", "URL", "label", label_map={"1": "legitimate", "0": "phishing"})
    read_csv(DOWNLOADS / "PhishBD_2026.csv",
             "PhishBD_2026", "dataset_eksternal", "url", "label", label_map={"1": "phishing", "0": "legitimate"})
    read_csv(DOWNLOADS / "dataset2.csv",
             "dataset2", "dataset_eksternal", "URL", "Label", label_map={"1": "phishing", "0": "legitimate"})
    read_csv(DOWNLOADS / "phishDB.csv",
             "phishDB", "dataset_eksternal", "url", "label", label_map={"1": "phishing", "0": "legitimate"})
    read_csv(DOWNLOADS / r"dataset_phishing.csv\dataset_phishing.csv",
             "dataset_B_2020", "dataset_eksternal", "url", "status")
    for path in sorted(DOWNLOADS.glob("verified_online*.csv")):
        read_csv(path, path.stem, "dataset_eksternal", "url", "verified",
                 label_map={"yes": "phishing"},
                 row_filter=lambda r: str(r.get("verified", "")).lower() == "yes")

    # Hanya hasil akhir pengujian, bukan .partial, .no_analysis, atau replay.
    for root in (DEPLOY / "data" / "evaluasi_live", EXPERIMENT, ROOT / "Heurishield-V5" / "reports" / "live-extension-eval"):
        if not root.exists():
            continue
        for path in root.rglob("browser_live_rows.csv"):
            low = str(path).lower()
            if any(k in low for k in ("_backup", "replay", "smoke", "audit", "gabungan", "_partial")):
                continue
            name = "uji_live:" + str(path.relative_to(root))
            with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as f:
                fields = next(csv.reader(f), [])
            age_col = next((c for c in ("source_domain_age_days", "original_domain_age_days") if c in fields), None)
            read_csv(path, name, "uji_live", "input_url", "expected_label", age_col,
                     age_rank=4, status_col="analysis_status")

    # Riwayat ekstraksi extension menyimpan label prediksi, bukan label aktual;
    # tidak dijadikan sumber label. Umurnya boleh mengisi URL yang sudah berlabel.
    history = DEPLOY / r"Heurisield\history-extract\hasil-ekstraksi.json"
    try:
        for item in json.loads(history.read_text(encoding="utf-8")):
            parsed = normalize_url(item.get("url", ""))
            if parsed and parsed[0] in records:
                age = usable_age(item.get("original_domain_age_days"))
                rec = records[parsed[0]]
                if age is not None and 4 > rec["age_rank"]:
                    rec["age"], rec["age_rank"] = age, 4
                    rec["age_source"] = "extension_history_prediction_age_only"
                rec["sources"].add("extension_history_age_only")
    except (OSError, ValueError, TypeError):
        pass

    total = Counter()
    with OUTPUT.open("w", encoding="utf-8-sig", newline="") as main_file, \
         AUDIT.open("w", encoding="utf-8-sig", newline="") as audit_file, \
         CONFLICTS.open("w", encoding="utf-8-sig", newline="") as conflict_file:
        main = csv.writer(main_file)
        audit = csv.writer(audit_file)
        conflict = csv.writer(conflict_file)
        main.writerow(["url", "label", "domain_age_days"])
        audit.writerow(["url", "label", "domain_age_days", "groups", "sources", "age_source", "source_rows", "test_statuses"])
        conflict.writerow(["url", "labels", "groups", "sources", "source_rows"])
        for key, rec in sorted(records.items()):
            groups = "|".join(sorted(rec["groups"]))
            sources = "|".join(sorted(rec["sources"]))
            if len(rec["labels"]) != 1:
                conflict.writerow([key, "|".join(sorted(rec["labels"])), groups, sources, rec["rows"]])
                total["conflict_urls"] += 1
                continue
            label = next(iter(rec["labels"]))
            age = rec["age"] if rec["age"] is not None else ""
            main.writerow([key, label, age])
            audit.writerow([key, label, age, groups, sources, rec["age_source"], rec["rows"], "|".join(sorted(rec["status"]))])
            total["unique_urls"] += 1
            total[label] += 1
            total["with_age" if age != "" else "without_age"] += 1
            if "uji_live" in rec["groups"]:
                total["also_in_live_history"] += 1
            if "dataset_eksternal" in rec["groups"]:
                total["from_external_dataset"] += 1
            if "pelatihan_lama" in rec["groups"] or "pelatihan_eksperimen" in rec["groups"]:
                total["from_training_corpus"] += 1

    summary = {"counts": dict(total), "source_stats": {k: dict(v) for k, v in source_stats.items()},
               "notes": ["Output menggabungkan korpus lama, eksperimen, pengujian live, dan kumpulan eksternal yang labelnya dapat dipetakan.",
                         "Konflik label URL yang sama dikeluarkan dari CSV utama.",
                         "Umur domain tidak selalu mengacu pada tanggal yang sama dan bukan data latih siap pakai.",
                         "Riwayat ekstraksi extension tidak menjadi sumber label aktual.",
                         "Sumber eksternal dan URL tanpa analisis live memerlukan verifikasi label/status sebelum menjadi data latih."]}
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary["counts"], ensure_ascii=False, indent=2))
    print("Sources:", len(source_stats))
    print("Saved:", OUTPUT, AUDIT, CONFLICTS, SUMMARY, sep="\n")


if __name__ == "__main__":
    main()
