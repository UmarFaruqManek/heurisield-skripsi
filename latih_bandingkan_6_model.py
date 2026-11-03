r"""Bandingkan enam model pada 18 fitur URL dengan pemisahan per situs.

Jalankan: python .\latih_bandingkan_6_model.py
Prediksi holdout dan keenam model disimpan di hasil_perbandingan_6_model/.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import time
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
import sklearn
import tldextract
import xgboost
from imodels import RuleFitClassifier
from sklearn.ensemble import ExtraTreesClassifier, HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, balanced_accuracy_score,
                             confusion_matrix, f1_score, precision_score, roc_auc_score)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from ekstrak_fitur_url import URL_FEATURES


ROOT = Path(__file__).resolve().parent
DATA = ROOT / "DATA_URL_18_FITUR.csv"
RESULT = ROOT / "hasil_perbandingan_6_model"
SEED = 20261031
FEATURES = [*URL_FEATURES, "domain_age_days"]
DOMAIN_PARSER = tldextract.TLDExtract(
    suffix_list_urls=(), include_psl_private_domains=True
)


def site_key(url: str) -> str:
    """Kelompok situs untuk mencegah URL situs yang sama masuk train dan test."""
    host = urlsplit(url).hostname or ""
    ext = DOMAIN_PARSER(host)
    return ext.top_domain_under_public_suffix or host


def choose_fold(y: np.ndarray, groups: np.ndarray, folds: int,
                target_class_rows: np.ndarray, seed: int) -> np.ndarray:
    """Pilih satu fold yang ukurannya paling dekat dengan target per kelas."""
    splitter = StratifiedGroupKFold(n_splits=folds, shuffle=True, random_state=seed)
    candidates = []
    for number, (_, selected) in enumerate(splitter.split(np.zeros(len(y)), y, groups)):
        actual = np.bincount(y[selected], minlength=2)
        deviation = np.abs(actual - target_class_rows) / np.maximum(target_class_rows, 1)
        candidates.append((float(deviation.sum()), number, selected))
    return min(candidates, key=lambda entry: (entry[0], entry[1]))[2]


def split_three_ways(y: np.ndarray, groups: np.ndarray):
    total_class = np.bincount(y, minlength=2)
    test = choose_fold(y, groups, 10, total_class * .10, SEED)
    rest = np.setdiff1d(np.arange(len(y)), test)
    val_local = choose_fold(y[rest], groups[rest], 9, total_class * .10, SEED + 1)
    validation = rest[val_local]
    train = np.setdiff1d(rest, validation)
    for first, second in ((train, validation), (train, test), (validation, test)):
        if set(groups[first]) & set(groups[second]):
            raise AssertionError("Situs yang sama masuk ke dua partisi")
    for indices in (train, validation, test):
        if set(y[indices]) != {0, 1}:
            raise AssertionError("Salah satu partisi tidak berisi kedua kelas")
    return train, validation, test


def class_scores(y: np.ndarray, prob: np.ndarray, threshold: float) -> dict:
    predicted = (prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, predicted, labels=[0, 1]).ravel()
    return {
        "rows": int(len(y)), "threshold": round(float(threshold), 4),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
        "accuracy_percent": round(100 * accuracy_score(y, predicted), 2),
        "balanced_accuracy_percent": round(100 * balanced_accuracy_score(y, predicted), 2),
        "legitimate_specificity_percent": round(100 * tn / (tn + fp), 2),
        "phishing_recall_percent": round(100 * tp / (tp + fn), 2),
        "false_positive_rate_percent": round(100 * fp / (tn + fp), 2),
        "phishing_precision_percent": round(100 * precision_score(y, predicted, zero_division=0), 2),
        "phishing_f1_percent": round(100 * f1_score(y, predicted, zero_division=0), 2),
        "roc_auc_percent": round(100 * roc_auc_score(y, prob), 2),
        "average_precision_percent": round(100 * average_precision_score(y, prob), 2),
    }


def choose_threshold(y: np.ndarray, prob: np.ndarray) -> float:
    # Utamakan kinerja kelas yang paling lemah, bukan akurasi gabungan saja.
    candidates = np.round(np.arange(.05, .951, .01), 2)
    ranked = []
    for threshold in candidates:
        s = class_scores(y, prob, float(threshold))
        minimum = min(s["legitimate_specificity_percent"], s["phishing_recall_percent"])
        ranked.append((minimum, s["balanced_accuracy_percent"],
                       -abs(float(threshold) - .5), float(threshold)))
    return max(ranked)[3]


def models():
    return {
        "LogisticRegression": make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=2000, random_state=SEED)),
        "RandomForest": RandomForestClassifier(
            n_estimators=250, min_samples_leaf=2, n_jobs=4, random_state=SEED),
        "ExtraTrees": ExtraTreesClassifier(
            n_estimators=250, min_samples_leaf=2, n_jobs=4, random_state=SEED),
        "HistGradientBoosting": HistGradientBoostingClassifier(
            max_iter=250, max_leaf_nodes=31, learning_rate=.05,
            l2_regularization=1., random_state=SEED),
        "XGBoost": XGBClassifier(
            n_estimators=350, max_depth=4, learning_rate=.05, subsample=.8,
            colsample_bytree=.9, tree_method="hist", objective="binary:logistic",
            eval_metric="logloss", n_jobs=4, random_state=SEED),
        # Ini pembanding yang mendekati keluarga RuleFit lama: aturan tanpa
        # komponen linear. Nilai 150 adalah batas kandidat aturan, bukan jumlah aktif.
        "RuleFit": RuleFitClassifier(
            tree_size=4, sample_fract="default", max_rules=150,
            memory_par=.01, lin_trim_quantile=.025,
            include_linear=False, random_state=SEED),
    }


def main() -> None:
    start = time.perf_counter()
    if not DATA.is_file():
        raise FileNotFoundError(DATA)
    df = pd.read_csv(DATA)
    required = {"url", "label", *FEATURES}
    if required - set(df.columns):
        raise ValueError(f"Kolom hilang: {required - set(df.columns)}")
    if df[FEATURES].isna().any().any() or df.url.duplicated().any():
        raise ValueError("Ada fitur kosong atau URL duplikat")
    if set(df.label) != {"legitimate", "phishing"}:
        raise ValueError("Label harus legitimate dan phishing")

    y = (df.label == "phishing").to_numpy(dtype=int)
    x = df[FEATURES].to_numpy(dtype=np.float64)
    groups = np.array([site_key(url) for url in df.url], dtype=object)
    train, validation, test = split_three_ways(y, groups)
    RESULT.mkdir(exist_ok=True)
    (RESULT / "model").mkdir(exist_ok=True)

    split_labels = np.full(len(df), "train", dtype=object)
    split_labels[validation] = "validation"
    split_labels[test] = "test"
    pd.DataFrame({"url": df.url, "label": df.label,
                  "site_key": groups, "split": split_labels}).to_csv(
        RESULT / "pembagian_data.csv", index=False)
    prediction_table = df.loc[test, ["url", "label", "domain_age_days"]].copy()
    prediction_table.insert(1, "site_key", groups[test])

    report = {
        "source": str(DATA),
        "source_sha256": hashlib.sha256(DATA.read_bytes()).hexdigest(),
        "seed": SEED, "feature_names": FEATURES, "feature_count": len(FEATURES),
        "split_unit": "registered site; private PSL enabled for pages.dev/blogspot.com/etc",
        "threshold_selection": "validation max min(specificity, recall); tie balanced accuracy",
        "threshold_candidates": "0.05..0.95 step 0.01",
        "partitions": {
            name: {"rows": int(len(indices)),
                   "legitimate": int((y[indices] == 0).sum()),
                   "phishing": int((y[indices] == 1).sum()),
                   "unique_sites": int(len(set(groups[indices])))}
            for name, indices in (("train", train), ("validation", validation), ("test", test))
        },
        "versions": {"numpy": np.__version__, "pandas": pd.__version__,
                     "scikit_learn": sklearn.__version__, "xgboost": xgboost.__version__},
        "limits": [
            "This is an internal offline holdout, not an independent live-browser test.",
            "The input was balanced before splitting; evaluation prevalence is not natural.",
            "Domain ages came from different observation dates and can describe a hosting platform.",
            "Some labels came from historic feeds or prior tests and were not reverified live.",
        ],
        "models": {},
    }

    for name, model in models().items():
        model_start = time.perf_counter()
        print(f"Melatih {name} ({len(train)} train, {len(validation)} validasi, {len(test)} uji)", flush=True)
        if name == "RuleFit":
            model.fit(x[train], y[train], feature_names=FEATURES)
        else:
            model.fit(x[train], y[train])
        val_prob = np.asarray(model.predict_proba(x[validation]))[:, 1]
        threshold = choose_threshold(y[validation], val_prob)
        test_prob = np.asarray(model.predict_proba(x[test]))[:, 1]
        if not np.isfinite(test_prob).all() or not np.isfinite(val_prob).all():
            raise ValueError(f"Probabilitas tidak valid: {name}")
        result = {
            "validation": class_scores(y[validation], val_prob, threshold),
            "test_selected_threshold": class_scores(y[test], test_prob, threshold),
            "test_threshold_0_50": class_scores(y[test], test_prob, .5),
            "training_and_prediction_seconds": round(time.perf_counter() - model_start, 2),
        }
        if name == "RuleFit":
            rules = model.get_rules()
            result["generated_rules"] = int((rules.type == "rule").sum())
            result["active_rules"] = int(((rules.type == "rule") & (rules.coef.abs() > 1e-12)).sum())
        report["models"][name] = result
        prediction_table[name + "_prob_phishing"] = test_prob
        prediction_table[name + "_label"] = np.where(test_prob >= threshold, "phishing", "legitimate")
        joblib.dump(model, RESULT / "model" / (name + ".joblib"), compress=3)
        (RESULT / "evaluasi_model.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        prediction_table.to_csv(RESULT / "prediksi_data_uji.csv", index=False)
        print(name, json.dumps(result["test_selected_threshold"], ensure_ascii=False), flush=True)

    # Model yang direkomendasikan dipilih dari validasi, bukan dari data uji.
    rank = sorted(report["models"], key=lambda name: (
        min(report["models"][name]["validation"]["legitimate_specificity_percent"],
            report["models"][name]["validation"]["phishing_recall_percent"]),
        report["models"][name]["validation"]["balanced_accuracy_percent"]), reverse=True)
    report["selected_by_validation"] = rank[0]
    report["validation_rank"] = rank
    report["total_seconds"] = round(time.perf_counter() - start, 2)
    (RESULT / "evaluasi_model.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    pd.DataFrame([
        {"model": name, **result["test_selected_threshold"],
         "fit_seconds": result["training_and_prediction_seconds"]}
        for name, result in report["models"].items()
    ]).sort_values("balanced_accuracy_percent", ascending=False).to_csv(
        RESULT / "perbandingan_model.csv", index=False)
    print("Hasil:", RESULT, "model pilihan validasi:", rank[0], flush=True)


if __name__ == "__main__":
    main()
