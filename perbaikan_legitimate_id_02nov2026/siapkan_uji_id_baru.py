"""Preflight unused ROR Indonesian websites for an independent .ac.id test list."""
from __future__ import annotations

import csv
import json
import random
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from siapkan_legitimate_fresh_500_02nov import prior_sites
from siapkan_legitimate_final_300 import verify_official_site
from siapkan_legitimate_stratified_300 import registry_records

OUT = Path(r"C:\Users\USER\Downloads\legitimate_indonesia_fresh_independent_200_02nov2026.txt")
CHECKPOINT = HERE / "uji_id_preflight.jsonl"


def main() -> None:
    seen, _ = prior_sites()
    sources = [row for row in registry_records(seen)
               if row["country"] == "ID" and row["site_key"].endswith(".ac.id")]
    accepted = {}
    processed = set()
    if CHECKPOINT.exists():
        for line in CHECKPOINT.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                processed.add(row["site_key"])
                if row.get("result") and row["site_key"] not in seen:
                    accepted[row["site_key"]] = row["result"]
    with CHECKPOINT.open("a", encoding="utf-8") as checkpoint:
        for offset in range(0, len(sources), 200):
            if len(accepted) >= 200:
                break
            batch = [row for row in sources[offset:offset + 200]
                     if row["site_key"] not in processed]
            with ThreadPoolExecutor(max_workers=48) as pool:
                futures = {pool.submit(verify_official_site, row): row for row in batch}
                for future in as_completed(futures):
                    item = futures[future]
                    try:
                        result = future.result()
                    except Exception:
                        result = None
                    checkpoint.write(json.dumps({"site_key": item["site_key"],
                                                 "result": result}, ensure_ascii=False) + "\n")
                    checkpoint.flush()
                    processed.add(item["site_key"])
                    if result:
                        accepted[item["site_key"]] = result
            print(f"Checked {len(processed)}; valid={len(accepted)}", flush=True)
    if len(accepted) < 200:
        raise RuntimeError(f"Only {len(accepted)} independent Indonesian sites passed preflight")
    selected = random.Random(20261102).sample(list(accepted.values()), 200)
    OUT.write_text("\n".join(row["url"] for row in selected) + "\n", encoding="utf-8")
    fields = ["url", "final_url", "site_key", "title", "organization", "source_ror",
              "sector", "country", "auth_in_url", "password_input_in_html", "checked_at_utc"]
    with (HERE / "audit_uji_id_baru_200.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(selected)
    print(json.dumps({"output": str(OUT), "rows": len(selected),
                      "unique_sites": len({row["site_key"] for row in selected}),
                      "checked": len(processed)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
