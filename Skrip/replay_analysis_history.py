"""Re-evaluate saved decisions without opening URLs or calling brand/WHOIS APIs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sqlite3
import subprocess
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


def percent(correct: int, count: int) -> float | None:
    return round(100 * correct / count, 2) if count else None


def metrics(rows: list[dict], verdict_key: str, label: str) -> dict:
    expected = "DANGEROUS" if label == "phishing" else "SAFE"
    cohort = [r for r in rows if r["expected_label"] == label and r["analysis_status"] == "completed"
              and (verdict_key != "new_verdict" or r["replay_level"] != "partial_api_snapshot")
              and r.get(verdict_key) in {"SAFE", "DANGEROUS"}]
    correct = sum(r[verdict_key] == expected for r in cohort)
    return {"evaluated": len(cohort), "correct": correct, "incorrect": len(cohort) - correct,
            "correct_percent": percent(correct, len(cohort))}


def replay(db_path: Path, extension_dir: Path, out_dir: Path, run_ids: list[str]) -> dict:
    with closing(sqlite3.connect(db_path)) as db:
        db.row_factory = sqlite3.Row
        selected = list(db.execute("SELECT * FROM runs WHERE extension_name=? ORDER BY generated_at",
                                   (extension_dir.name,)))
        if run_ids:
            selected = [r for r in selected if r["run_id"] in run_ids]
        if not selected:
            raise ValueError(f"Tidak ada arsip untuk extension {extension_dir.name} di {db_path}")
        rows = []
        for run in selected:
            for record in db.execute("SELECT * FROM analyses WHERE run_id=? ORDER BY url_index", (run["run_id"],)):
                rows.append({"run_id": run["run_id"], "index": record["url_index"],
                             "url": record["url"], "expected_label": record["expected_label"],
                             "analysis_status": record["analysis_status"],
                             "old_verdict": record["observed_verdict"],
                             "analysis": json.loads(record["analysis_json"]) if record["analysis_json"] else None})

    runner = extension_dir / "tools" / "replay-decisions.mjs"
    result = subprocess.run(["node", str(runner)], input=json.dumps({"records": rows}),
                            text=True, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError(f"Replay JS gagal: {result.stderr[:2000]}")
    replayed = json.loads(result.stdout)["records"]
    for old, current in zip(rows, replayed, strict=True):
        current["run_id"] = old["run_id"]
        expected = "DANGEROUS" if old["expected_label"] == "phishing" else "SAFE"
        current["old_correct"] = old["analysis_status"] == "completed" and old["old_verdict"] == expected
        current["new_correct"] = old["analysis_status"] == "completed" and current["new_verdict"] == expected

    model_path = extension_dir / "src" / "model" / "xgboost-url18.json"
    model_hash = hashlib.sha256(model_path.read_bytes()).hexdigest() if model_path.is_file() else None
    different_models = [r["run_id"] for r in selected if r["model_sha256"] and r["model_sha256"] != model_hash]
    summary = {
        "mode": "offline_decision_replay_no_network",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "database": str(db_path), "extension": str(extension_dir),
        "run_ids": [r["run_id"] for r in selected], "total_urls": len(replayed),
        "replay_levels": {level: sum(r["replay_level"] == level for r in replayed)
                          for level in sorted({r["replay_level"] for r in replayed})},
        "no_analysis": sum(r["analysis_status"] != "completed" for r in replayed),
        "excluded_partial_api_snapshot": sum(r["replay_level"] == "partial_api_snapshot" for r in replayed),
        "changed_decisions": sum(r.get("changed") is True for r in replayed),
        "different_model_snapshots": different_models,
        "by_label": {label: {"old": metrics(replayed, "old_verdict", label),
                             "replay": metrics(replayed, "new_verdict", label)}
                     for label in ("legitimate", "phishing")},
        "limits": [
            "Hanya keputusan DOM/brand/rule yang diputar ulang; prediksi model URL memakai hasil saat uji live.",
            "decision_only berarti arsip lama tidak menyimpan snapshot DOM dan hasil API untuk menghitung ulang ekstraksi.",
            "partial_api_snapshot berarti aturan baru meminta informasi API yang tidak ada dalam arsip; hasil perlu ditinjau.",
            "Data yang telah dipakai untuk perbaikan merupakan data pengembangan, bukan uji eksternal independen."
        ]
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "ringkasan_replay.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    columns = ["run_id", "index", "url", "expected_label", "analysis_status", "url_model_verdict",
               "old_verdict", "new_verdict", "old_correct", "new_correct", "changed", "replay_level",
               "missing_saved_lookups", "old_source", "new_source", "matched_rules", "review_candidate",
               "brand_status", "official_domain_match", "dom_sensitive", "reason"]
    with (out_dir / "per_url_replay.csv").open("w", encoding="utf-8-sig", newline="") as dest:
        writer = csv.DictWriter(dest, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in replayed:
            writer.writerow({**row, "matched_rules": ",".join(row.get("matched_rules") or []),
                             "missing_saved_lookups": ",".join(row.get("missing_saved_lookups") or [])})
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=Path(r"D:\experimen\ide bagus\database_evaluasi\riwayat_analisis.sqlite"))
    parser.add_argument("--extension-dir", type=Path,
                        default=Path(r"D:\experimen\ide bagus\HeuriShield-URL18-XGBoost"))
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--run-id", action="append", default=[])
    args = parser.parse_args()
    target = args.out_dir or args.db.parent / f"hasil_replay_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    print(json.dumps(replay(args.db, args.extension_dir, target, args.run_id),
                     ensure_ascii=False, indent=2))
    print(f"Detail: {target / 'per_url_replay.csv'}")


if __name__ == "__main__":
    main()
