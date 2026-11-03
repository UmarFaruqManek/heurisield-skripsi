"""Audit the Indonesian live cohort and train a domain-separated URL18 candidate.

The live cohort is development evidence. This script never changes the active
extension or starts a browser. It uses only archived URLs, snapshots and ROR
references already stored by the preparation/evaluation pipeline.
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
import tldextract
from sklearn.model_selection import GroupShuffleSplit
from xgboost import XGBClassifier

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
LIVE = ROOT / "hasil_live_final/url18_legitimate_id_20261102_222018/browser_live_analysis.json"
AUDIT = ROOT / "persiapan_legitimate_indonesia_300_02nov2026/audit_300.csv"
DATA = ROOT / "DATA_URL_18_FITUR.csv"
SPLITS = ROOT / "hasil_perbandingan_6_model/pembagian_data.csv"
MODEL = ROOT / "hasil_perbandingan_6_model/model/XGBoost.joblib"
FEATURES = json.loads((ROOT / "HeuriShield-URL18-XGBoost/src/model/xgboost-url18.json").read_text())["feature_names"]
DEVELOPMENT_WEIGHT = 16
PRIVATE_PHISHING_WEIGHT = 4
GENERIC = {"institut", "sekolah", "tinggi", "universitas", "politeknik", "akademi", "agama", "islam", "negeri", "indonesia", "kesehatan", "teknologi", "pendidikan", "kabupaten", "daerah", "the", "of", "and", "dan", "pusat", "badan", "riset", "rumah", "sakit", "mahasiswa", "login", "beranda", "home", "website", "page", "resmi"}


def tokens(value: str) -> set[str]:
    return {word for word in re.findall(r"[a-z0-9]+", value.lower())
            if len(word) >= 4 and word not in GENERIC}


def audit_rows() -> pd.DataFrame:
    live = json.loads(LIVE.read_text(encoding="utf-8-sig"))["records"]
    with AUDIT.open(encoding="utf-8-sig", newline="") as handle:
        reference = {row["url"]: row for row in csv.DictReader(handle)}
    rows = []
    for record in live:
        original = record["input_url"]
        ref = reference.get(original)
        if ref is None:
            raise ValueError(f"Missing preparation record: {original}")
        analysis = record.get("analysis") or {}
        snapshot = (analysis.get("replay_evidence") or {}).get("main_snapshot") or {}
        title = str(snapshot.get("title") or "")
        host = urlsplit(original).hostname or ""
        observed_host = urlsplit(snapshot.get("page_origin") or "").hostname or ""
        prepared_host = urlsplit(ref["final_url"]).hostname or ""
        statuses = record.get("document_status") or {}
        http_ok = statuses.get(original) == 200 or statuses.get(ref["final_url"]) == 200
        same_host = host == observed_host == prepared_host
        distinctive = tokens(ref["organization"]) & (tokens(title) | tokens(host.replace(".", " ")))
        error_page = bool(re.search(r"(?:site not found|404 not found|error 404|403 forbidden|suspended|account disabled|sedang perbaikan|maintenance)", title, re.I))
        ror = ref["source_ror"].startswith("https://ror.org/")
        # This is evidence of organizational identity, not a guarantee that
        # the site was uncompromised when the page was captured.
        supported = (record["analysis_status"] == "completed" and http_ok
                     and same_host and ror and bool(distinctive) and not error_page)
        rows.append({
            "index": record["index"], "url": original, "site_key": ref["site_key"],
            "expected_label": "legitimate", "observed_verdict": record["observed_verdict"],
            "analysis_status": record["analysis_status"], "organization": ref["organization"],
            "ror_source": ref["source_ror"], "prepared_title": ref["title"],
            "captured_title": title, "captured_origin": snapshot.get("page_origin") or "",
            "http_200": http_ok, "same_host": same_host,
            "matching_identity_tokens": ",".join(sorted(distinctive)),
            "label_audit": "supported_archive" if supported else "manual_review",
            "reason": "ror_host_title_http" if supported else
                      "no_completed_analysis" if record["analysis_status"] != "completed" else
                      "http_or_host_mismatch" if not (http_ok and same_host) else
                      "missing_ror_reference" if not ror else
                      "error_or_maintenance_page" if error_page else "identity_not_confirmed_from_title",
            "probability_phishing": record.get("probability_phishing"),
            **{feature: (record.get("features_raw") or {}).get(feature) for feature in FEATURES},
        })
    result = pd.DataFrame(rows)
    result.to_csv(HERE / "audit_300.csv", index=False, encoding="utf-8-sig")
    return result


def scores(y: np.ndarray, prob: np.ndarray, threshold: float) -> dict:
    positive = prob >= threshold
    legitimate = y == 0
    phishing = y == 1
    return {"threshold": float(threshold), "legitimate": int(legitimate.sum()),
            "legitimate_correct": int((legitimate & ~positive).sum()),
            "legitimate_specificity_percent": round(100 * (legitimate & ~positive).sum() / legitimate.sum(), 2) if legitimate.any() else None,
            "phishing": int(phishing.sum()), "phishing_correct": int((phishing & positive).sum()),
            "phishing_recall_percent": round(100 * (phishing & positive).sum() / phishing.sum(), 2) if phishing.any() else None}


def archived_rows(folder: Path) -> tuple[np.ndarray, np.ndarray, list[str]]:
    payload = json.loads((folder / "browser_live_analysis.json").read_text(encoding="utf-8-sig"))
    rows = [r for r in payload["records"] if r["analysis_status"] == "completed"
            and r.get("features_raw") and r.get("actual_label") in ("legitimate", "phishing")]
    x = np.array([[r["features_raw"].get(feature, np.nan) if r["features_raw"].get(feature) is not None else np.nan
                   for feature in FEATURES] for r in rows], dtype=float)
    y = np.array([int(r["actual_label"] == "phishing") for r in rows])
    return x, y, [r["input_url"] for r in rows]


def train_candidate(audit: pd.DataFrame) -> None:
    base = pd.read_csv(DATA)
    split = pd.read_csv(SPLITS)
    if len(base) != len(split) or not np.array_equal(base.url.to_numpy(), split.url.to_numpy()):
        raise ValueError("Original domain split does not align with the training data")
    additions = audit[audit.label_audit == "supported_archive"].copy()
    if additions[FEATURES].isna().any().any():
        raise ValueError("A supported archive row lacks a feature")
    existing_sites = set(split.site_key)
    overlap = sorted(set(additions.site_key) & existing_sites)
    if overlap:
        raise ValueError(f"Development domains overlap original model splits: {overlap[:5]}")
    if additions.site_key.duplicated().any():
        raise ValueError("New cohort must use one URL per registered site")
    dev_train_index, dev_holdout_index = next(GroupShuffleSplit(
        n_splits=1, test_size=.30, random_state=20261102).split(additions,
            groups=additions.site_key))
    dev_train = additions.iloc[dev_train_index]
    dev_holdout = additions.iloc[dev_holdout_index]
    original_train = base[split.split == "train"]
    original_validation = base[split.split == "validation"]
    original_test = base[split.split == "test"]
    x_train = np.vstack((original_train[FEATURES].to_numpy(dtype=float),
                         dev_train[FEATURES].to_numpy(dtype=float)))
    y_train = np.concatenate(((original_train.label == "phishing").to_numpy(dtype=int),
                              np.zeros(len(dev_train), dtype=int)))
    model = XGBClassifier(n_estimators=350, max_depth=4, learning_rate=.05,
                          subsample=.8, colsample_bytree=.9, tree_method="hist",
                          objective="binary:logistic", eval_metric="logloss",
                          n_jobs=4, random_state=20261031)
    parser = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
    private_phishing = np.array([
        row.label == "phishing" and parser(urlsplit(row.url).hostname or "").is_private
        for row in original_train.itertuples()])
    weights = np.r_[np.where(private_phishing, PRIVATE_PHISHING_WEIGHT, 1.),
                    np.full(len(dev_train), DEVELOPMENT_WEIGHT)]
    model.fit(x_train, y_train, sample_weight=weights)
    baseline = joblib.load(MODEL)
    xv = original_validation[FEATURES].to_numpy(dtype=float)
    yv = (original_validation.label == "phishing").to_numpy(dtype=int)
    validation_prob = model.predict_proba(xv)[:, 1]
    # Select threshold on the original validation partition only. The new
    # Indonesian holdout and archived phishing runs are diagnostic gates.
    ranked = []
    for threshold in np.arange(.05, .951, .01):
        s = scores(yv, validation_prob, round(float(threshold), 2))
        floor = min(s["legitimate_specificity_percent"], s["phishing_recall_percent"])
        ranked.append((floor, (s["legitimate_specificity_percent"] + s["phishing_recall_percent"]) / 2, -abs(threshold - .5), round(float(threshold), 2)))
    threshold = max(ranked)[3]
    cohorts = {
        "original_validation": (xv, yv),
        "original_test": (original_test[FEATURES].to_numpy(dtype=float),
                          (original_test.label == "phishing").to_numpy(dtype=int)),
        "indonesia_dev_holdout": (dev_holdout[FEATURES].to_numpy(dtype=float),
                                   np.zeros(len(dev_holdout), dtype=int)),
    }
    for key, folder in {
        "prior_legitimate_500": ROOT / "hasil_live_legitimate_fresh_500_02nov2026",
        "prior_legitimate_300": ROOT / "hasil_live_final/url18_v028_legitimate_20261102_210320",
        "prior_phishing_183": ROOT / "hasil_live_phishunt_baru_02nov2026",
        "prior_phishing_300": ROOT / "hasil_live_dual_01nov2026/phishing_xgboost18_v026_01nov2026",
    }.items():
        cohorts[key] = archived_rows(folder)[:2]
    report = {"source_sha256": hashlib.sha256(DATA.read_bytes()).hexdigest(),
              "audit_counts": audit.label_audit.value_counts().to_dict(),
              "development_train_added": len(dev_train),
              "development_holdout": len(dev_holdout),
              "development_sample_weight": DEVELOPMENT_WEIGHT,
              "private_phishing_sample_weight": PRIVATE_PHISHING_WEIGHT,
              "private_phishing_train_rows": int(private_phishing.sum()),
              "threshold_selected_from_original_validation": threshold,
              "cohorts": {}, "candidate_deployable": False,
              "limits": ["The 300 Indonesian URLs are development data after this analysis.",
                         "An ROR-linked site and matching title do not prove the page was uncompromised.",
                         "Archived phishing is a development gate, not a fresh external live test."]}
    for name, (x, y) in cohorts.items():
        report["cohorts"][name] = {
            "baseline": scores(y, baseline.predict_proba(x)[:, 1], .38),
            "candidate": scores(y, model.predict_proba(x)[:, 1], threshold)}
    joblib.dump(model, HERE / "candidate_XGBoost.joblib", compress=3)
    from export_xgboost_url18 import export
    export(model, FEATURES, threshold, HERE / "candidate_xgboost-url18.json")
    (HERE / "evaluation.json").write_text(json.dumps(report, indent=2,
        ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    result = audit_rows()
    print("Audit:", result.label_audit.value_counts().to_dict())
    train_candidate(result)
