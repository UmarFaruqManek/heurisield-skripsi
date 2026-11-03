"""Prepare independent legitimate URLs from prior ROR preflight checkpoints.

No extension/browser evaluation is run. The output is excluded by registered
site from model training, prior CSV audit files, and the Excel test history.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from siapkan_legitimate_fresh_500_02nov import prior_sites
from siapkan_legitimate_stratified_300 import balanced_pick

HERE = Path(__file__).resolve().parent
CHECKPOINTS = [
    ROOT / "persiapan_legitimate_stratified_02nov2026/pemeriksaan_website.jsonl",
    ROOT / "persiapan_legitimate_fresh_500_02nov2026/pemeriksaan_website.jsonl",
    ROOT / "persiapan_legitimate_final_300_02nov2026/pemeriksaan_tambahan.jsonl",
]
OUT = Path(r"C:\Users\USER\Downloads\legitimate_fresh_independent_300_02nov2026.txt")


def main() -> None:
    excluded, _ = prior_sites()
    by_site = {}
    for path in CHECKPOINTS:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("result") and record["site_key"] not in excluded:
                by_site[record["site_key"]] = record["result"]
    if len(by_site) < 300:
        raise RuntimeError(f"Only {len(by_site)} unique unused sites available")
    selected = balanced_pick(list(by_site.values()), 300)
    if len(selected) != 300 or len({row["site_key"] for row in selected}) != 300:
        raise RuntimeError("Selection failed to produce 300 distinct sites")
    if any(row["site_key"] in excluded for row in selected):
        raise RuntimeError("A prior site leaked into the new evaluation set")
    OUT.write_text("\n".join(row["url"] for row in selected) + "\n", encoding="utf-8")
    fields = ["url", "final_url", "site_key", "title", "organization", "source_ror",
              "sector", "country", "auth_in_url", "password_input_in_html", "checked_at_utc"]
    with (HERE / "audit_uji_baru_300.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(selected)
    summary = {"output": str(OUT), "rows": len(selected),
               "unique_registered_sites": len({row["site_key"] for row in selected}),
               "sectors": dict(Counter(row["sector"] for row in selected)),
               "countries": dict(Counter(row["country"] for row in selected)),
               "account_paths": sum(bool(row["auth_in_url"]) for row in selected),
               "password_inputs": sum(bool(row["password_input_in_html"]) for row in selected),
               "limits": "ROR and earlier HTTP preflight support the labels; live availability and extension coverage are not guaranteed."}
    (HERE / "uji_baru_summary.json").write_text(json.dumps(summary, indent=2,
        ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
