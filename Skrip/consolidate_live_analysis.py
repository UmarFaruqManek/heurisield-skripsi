#!/usr/bin/env python3
"""Gabungkan bukti pengujian live menjadi satu JSON tanpa membuka ulang URL."""

from __future__ import annotations

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path


def consolidate_live_analysis(out_dir: Path) -> Path:
    out_dir = Path(out_dir)
    raw_path = out_dir / "browser_live_raw_analysis.jsonl"
    rows_path = out_dir / "browser_live_rows.csv"
    if not rows_path.is_file():
        rows_path = out_dir / "browser_live_rows.partial.csv"
    summary_path = out_dir / "browser_live_summary.json"
    if not rows_path.is_file():
        raise FileNotFoundError(rows_path)

    raw_by_index = {}
    if raw_path.is_file():
        with raw_path.open(encoding="utf-8") as source:
            for line_number, line in enumerate(source, start=1):
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"JSONL tidak valid pada baris {line_number}: {exc}") from exc
                raw_by_index[str(item["index"])] = item

    with rows_path.open(encoding="utf-8-sig", newline="") as source:
        rows = list(csv.DictReader(source))
    summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.is_file() else None
    manifest_path = out_dir / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else None
    snapshot_name = (manifest or {}).get("model_snapshot") or "model_snapshot_rulefit-engine-60.json"
    snapshot_path = out_dir / snapshot_name
    engine = json.loads(snapshot_path.read_text(encoding="utf-8")) if snapshot_path.is_file() and "rulefit" in snapshot_name.lower() else None

    records = []
    for row in rows:
        raw = raw_by_index.get(row["index"], {})
        analysis = raw.get("analysis")
        vector = (analysis or {}).get("feature_vector") or {}
        model = (analysis or {}).get("model_result") or {}
        status = row.get("analysis_status") or raw.get("analysis_status") or "unknown"
        # Pada RuleFit60, vector adalah 60 nilai mentah; median baru diterapkan
        # ketika syarat aturan dievaluasi. raw_vector hanya ada pada varian lama.
        raw_features = vector.get("raw_vector") or vector.get("vector")
        used_features = None
        if isinstance(raw_features, dict) and engine:
            medians = engine.get("imputer_median") or {}
            used_features = {name: (medians.get(name, 0) if value is None else value)
                             for name, value in raw_features.items()}
        elif isinstance(raw_features, dict):
            # XGBoost accepts missing values natively; a null age remains null.
            used_features = raw_features
        records.append({
            "index": int(row["index"]),
            "input_url": row.get("input_url"),
            "actual_label": row.get("expected_label"),
            "observed_verdict": row.get("actual_verdict") or None,
            "model_predicted_label": model.get("predicted_label") if status == "completed" else None,
            "correct_observed_verdict": (row.get("correct") == "1") if row.get("actual_verdict") else None,
            "analysis_status": status,
            "browser_final_url": row.get("browser_final_url") or None,
            "page_title": row.get("page_title") or raw.get("page_title") or None,
            "document_status": raw.get("document_status") or None,
            "analyzed_at": (analysis or {}).get("analyzed_at"),
            "feature_count": vector.get("feature_count") if analysis else None,
            "features_raw": raw_features if analysis else None,
            "features_used_by_model": used_features,
            "imputed_features": (vector.get("imputed_features") or vector.get("missing_features")) if analysis else None,
            "probability_phishing": model.get("probability_phishing") if status == "completed" else None,
            "threshold": model.get("threshold") if status == "completed" else None,
            "explanation": (analysis or {}).get("explanation"),
            "analysis": analysis,
            "error": row.get("error") or None,
        })

    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "note": "actual_label berasal dari daftar uji; model_predicted_label hanya tersedia untuk analisis model lengkap. URL tanpa analisis tetap tercatat.",
        "summary": summary,
        "partial_run": rows_path.name.endswith(".partial.csv"),
        "run_manifest": manifest,
        "record_count": len(records),
        "records": records,
    }
    target = out_dir / "browser_live_analysis.json"
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    temporary.replace(target)
    return target


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True, type=Path)
    print(consolidate_live_analysis(parser.parse_args().out_dir))
