"""Replace verified Indonesian homepages with their own live account links when available."""
from __future__ import annotations

import csv
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from siapkan_legitimate_stratified_300 import inspect_website
from siapkan_100_legitimate_xgboost import site_key

BASE = HERE / "persiapan_legitimate_indonesia_300_02nov2026"
AUDIT = BASE / "audit_300.csv"
OUTPUT = Path(r"C:\Users\USER\Downloads\legitimate_indonesia_fresh_300_02nov2026.txt")
SUMMARY = BASE / "ringkasan.json"


def main() -> None:
    with AUDIT.open(encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.DictReader(stream))
    changed = 0
    with ThreadPoolExecutor(max_workers=64) as pool:
        futures = {pool.submit(inspect_website, {**row, "source_url": row["url"]}): i
                   for i, row in enumerate(rows)}
        for future in as_completed(futures):
            index = futures[future]
            try:
                found = future.result()
            except Exception:
                continue
            if not found or site_key(found["url"]) != rows[index]["site_key"]:
                continue
            rows[index].update({key: str(found.get(key, rows[index].get(key, "")))
                                for key in ("url", "final_url", "title", "auth_in_url",
                                            "password_input_in_html", "checked_at_utc")})
            changed += 1
    assert len(rows) == 300 and len({row["site_key"] for row in rows}) == 300
    with AUDIT.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    OUTPUT.write_text("\n".join(row["url"] for row in rows) + "\n", encoding="utf-8")
    summary = json.loads(SUMMARY.read_text(encoding="utf-8"))
    summary.update({"linked_account_pages": changed,
                    "account_paths": sum(row["auth_in_url"].lower() == "true" for row in rows),
                    "password_inputs": sum(row["password_input_in_html"].lower() == "true" for row in rows),
                    "upgraded_at_utc": datetime.now(timezone.utc).isoformat()})
    SUMMARY.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"linked_account_pages": changed,
                      "account_paths": summary["account_paths"],
                      "password_inputs": summary["password_inputs"]}), flush=True)


if __name__ == "__main__":
    main()
