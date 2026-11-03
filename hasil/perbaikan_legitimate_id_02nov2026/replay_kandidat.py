"""Replay the candidate URL model with the current Brand/DOM policy on saved data."""
from __future__ import annotations

import copy
import json
import sqlite3
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
DB = ROOT / "hasil/database_evaluasi/riwayat_analisis.sqlite"
EXT = ROOT / "extension/HeuriShield-URL18-XGBoost"
FEATURES = json.loads((HERE / "candidate_xgboost-url18.json").read_text())["feature_names"]
THRESHOLD = json.loads((HERE / "candidate_xgboost-url18.json").read_text())["threshold"]


def node_replay(records: list[dict]) -> list[dict]:
    child = subprocess.run(["node", str(EXT / "tools/replay-decisions.mjs")],
                           input=json.dumps({"records": records}), text=True,
                           capture_output=True, cwd=EXT, check=True)
    return json.loads(child.stdout)["records"]


def main() -> None:
    candidate = joblib.load(HERE / "candidate_XGBoost.joblib")
    baseline = joblib.load(ROOT / "hasil/hasil_perbandingan_6_model/model/XGBoost.joblib")
    con = sqlite3.connect(DB)
    records = []
    run_names = {}
    for run_id, name in con.execute("SELECT run_id, report_dir FROM runs"):
        run_names[run_id] = Path(name).name
    for run_id, index, url, label, status, observed, source in con.execute(
            "SELECT run_id,url_index,url,expected_label,analysis_status,"
            "observed_verdict,analysis_json FROM analyses ORDER BY run_id,url_index"):
        if status != "completed" or not source:
            continue
        analysis = json.loads(source)
        if analysis.get("model_result", {}).get("model_family") != "XGBoost":
            continue
        values = (analysis.get("feature_vector") or {}).get("vector") or {}
        if set(FEATURES) - set(values):
            continue
        records.append({"run_id": run_id, "index": index, "url": url,
                        "expected_label": label, "analysis_status": status,
                        "old_verdict": observed, "analysis": analysis,
                        "vector": [values[feature] if values[feature] is not None else np.nan
                                   for feature in FEATURES]})
    x = np.asarray([r["vector"] for r in records], dtype=float)
    base_prob = baseline.predict_proba(x)[:, 1]
    new_prob = candidate.predict_proba(x)[:, 1]
    difference = max(abs(float(p) - r["analysis"]["model_result"]["probability_phishing"])
                     for p, r in zip(base_prob, records))
    if difference > 1e-5:
        raise ValueError(f"Saved model scores differ from baseline: {difference}")
    before, after = [], []
    for row, p_old, p_new in zip(records, base_prob, new_prob):
        base = {key: row[key] for key in ("index", "url", "expected_label", "analysis_status", "old_verdict")}
        old = copy.deepcopy(row["analysis"])
        new = copy.deepcopy(row["analysis"])
        old["model_result"]["probability_phishing"] = float(p_old)
        old["model_result"]["verdict"] = "DANGEROUS" if p_old >= .38 else "SAFE"
        new["model_result"]["probability_phishing"] = float(p_new)
        new["model_result"]["verdict"] = "DANGEROUS" if p_new >= THRESHOLD else "SAFE"
        before.append({**base, "analysis": old})
        after.append({**base, "analysis": new})
    old_result, new_result = node_replay(before), node_replay(after)
    summary = defaultdict(lambda: {"replayable": 0, "baseline_correct": 0,
                                   "candidate_correct": 0, "legitimate_to_safe": 0,
                                   "phishing_to_safe": 0, "phishing_to_dangerous": 0})
    changes = []
    for item, old, new in zip(records, old_result, new_result):
        if old["replay_level"] == "not_replayable" or new["replay_level"] == "not_replayable":
            continue
        group = summary[run_names[item["run_id"]]]
        group["replayable"] += 1
        target = "DANGEROUS" if item["expected_label"] == "phishing" else "SAFE"
        group["baseline_correct"] += old["new_verdict"] == target
        group["candidate_correct"] += new["new_verdict"] == target
        if old["new_verdict"] != new["new_verdict"]:
            key = ("legitimate_to_safe" if target == "SAFE" else
                   "phishing_to_safe" if new["new_verdict"] == "SAFE" else "phishing_to_dangerous")
            group[key] += 1
            changes.append({"run": run_names[item["run_id"]], "url": item["url"],
                            "label": item["expected_label"],
                            "baseline": old["new_verdict"], "candidate": new["new_verdict"],
                            "replay_level": new["replay_level"]})
    report = {"candidate_threshold": THRESHOLD, "model_score_max_difference": difference,
              "runs": dict(summary), "changes": changes,
              "replay_limit": "Saved DOM and API responses only; partial snapshots can lack lookups."}
    (HERE / "replay_evaluation.json").write_text(json.dumps(report, indent=2,
        ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"candidate_threshold": THRESHOLD, "runs": report["runs"],
                      "changes": len(changes)}, indent=2))


if __name__ == "__main__":
    main()
