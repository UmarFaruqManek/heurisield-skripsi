"""One durable SQLite archive for live-extension evidence and later offline replay."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SECRET_KEY = re.compile(r"code|state|token|secret|nonce|key|password|pass|otp|auth|session|ticket|credential|client_id|redirect_uri", re.I)


def safe_url(value: str | None) -> str:
    if not value:
        return ""
    try:
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            return ""
        query = urlencode([(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
                           if not SECRET_KEY.search(k)])
        netloc = parts.hostname + (f":{parts.port}" if parts.port else "")
        return urlunsplit((parts.scheme, netloc, parts.path, query, ""))
    except (ValueError, TypeError):
        return ""


def import_report(db_path: Path, report_dir: Path) -> tuple[str, int]:
    db_path, report_dir = Path(db_path), Path(report_dir)
    audit = json.loads((report_dir / "browser_live_analysis.json").read_text(encoding="utf-8"))
    manifest = audit.get("run_manifest") or {}
    summary = audit.get("summary") or {}
    run_id = hashlib.sha256(str(report_dir.resolve()).encode("utf-8")).hexdigest()[:20]
    snapshot_name = manifest.get("model_snapshot") or ""
    snapshot = report_dir / snapshot_name
    model_hash = hashlib.sha256(snapshot.read_bytes()).hexdigest() if snapshot.is_file() else ""
    extension_name = Path(manifest.get("extension_dir") or "unknown").name
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(db_path)) as connection, connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY, extension_name TEXT NOT NULL, report_dir TEXT NOT NULL,
                generated_at TEXT, expected_label TEXT, input_sha256 TEXT, model_sha256 TEXT,
                model_snapshot TEXT, manifest_json TEXT NOT NULL, summary_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS analyses (
                run_id TEXT NOT NULL REFERENCES runs(run_id), url_index INTEGER NOT NULL,
                url TEXT, url_sha256 TEXT NOT NULL, expected_label TEXT, analysis_status TEXT,
                observed_verdict TEXT, browser_final_url TEXT, site_http_status INTEGER,
                analysis_json TEXT, record_json TEXT NOT NULL,
                PRIMARY KEY (run_id, url_index)
            );
            CREATE INDEX IF NOT EXISTS analyses_label_status ON analyses(expected_label, analysis_status);
        """)
        connection.execute("""INSERT OR REPLACE INTO runs VALUES (?,?,?,?,?,?,?,?,?,?)""", (
            run_id, extension_name, str(report_dir.resolve()), summary.get("generated_at") or audit.get("generated_at"),
            summary.get("label") or next((r.get("actual_label") for r in audit.get("records", []) if r.get("actual_label")), None),
            manifest.get("input_sha256"), model_hash, snapshot_name,
            json.dumps(manifest, ensure_ascii=False), json.dumps(summary, ensure_ascii=False)))
        connection.execute("DELETE FROM analyses WHERE run_id=?", (run_id,))
        for record in audit.get("records") or []:
            raw_url = record.get("input_url") or ""
            clean = dict(record)
            clean["input_url"] = safe_url(raw_url)
            clean["browser_final_url"] = safe_url(record.get("browser_final_url"))
            clean["document_status"] = {safe_url(url): status for url, status
                                        in (record.get("document_status") or {}).items() if safe_url(url)}
            analysis = clean.get("analysis")
            connection.execute("""INSERT INTO analyses VALUES (?,?,?,?,?,?,?,?,?,?,?)""", (
                run_id, int(record["index"]), clean["input_url"],
                hashlib.sha256(raw_url.encode("utf-8")).hexdigest(),
                record.get("actual_label"), record.get("analysis_status"),
                record.get("observed_verdict"), clean["browser_final_url"],
                record.get("site_http_status") or next((status for status in reversed(list(clean["document_status"].values()))), None),
                json.dumps(analysis, ensure_ascii=False) if analysis is not None else None,
                json.dumps(clean, ensure_ascii=False)))
    return run_id, len(audit.get("records") or [])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    load = sub.add_parser("import")
    load.add_argument("--db", required=True, type=Path)
    load.add_argument("--report-dir", required=True, type=Path)
    stats = sub.add_parser("stats")
    stats.add_argument("--db", required=True, type=Path)
    args = parser.parse_args()
    if args.command == "import":
        run_id, count = import_report(args.db, args.report_dir)
        print(json.dumps({"database": str(args.db), "run_id": run_id, "records": count}))
    else:
        with closing(sqlite3.connect(args.db)) as connection:
            for row in connection.execute("""SELECT r.run_id,r.extension_name,r.expected_label,
                COUNT(a.url_index),SUM(a.analysis_status='completed'),
                SUM(a.observed_verdict='DANGEROUS') FROM runs r
                LEFT JOIN analyses a ON a.run_id=r.run_id GROUP BY r.run_id
                ORDER BY r.generated_at"""):
                print(json.dumps(dict(zip(("run_id","extension","label","total","evaluated","dangerous"), row))))


if __name__ == "__main__":
    main()
