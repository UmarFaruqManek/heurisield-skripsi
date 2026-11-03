"""Prepare fresh Indonesian organization sites for URL18 live evaluation."""
from __future__ import annotations

import csv
import hashlib
import json
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from siapkan_100_legitimate_xgboost import site_key
from siapkan_legitimate_fresh_500_02nov import prior_sites
from siapkan_legitimate_final_300 import fresh_candidates, verify, verify_official_site
from siapkan_legitimate_stratified_300 import registry_records

BASE = HERE / "persiapan_legitimate_indonesia_300_02nov2026"
BASE.mkdir(exist_ok=True)
OUTPUT = Path(r"C:\Users\USER\Downloads\legitimate_indonesia_fresh_300_02nov2026.txt")
RESERVE = Path(r"C:\Users\USER\Downloads\legitimate_indonesia_cadangan_02nov2026.txt")


def main() -> None:
    seen, exclusion_audit = prior_sites()
    # The previous batch's reserve has no CSV audit, so exclude it explicitly.
    previous_reserve = Path(r"C:\Users\USER\Downloads\legitimate_final_300_cadangan_02nov2026.txt")
    if previous_reserve.exists():
        seen.update(site_key(url.strip()) for url in previous_reserve.read_text(encoding="utf-8").splitlines() if url.strip())

    registry = {item["site_key"]: item for item in registry_records(seen)
                if item["country"] == "ID" and item["site_key"] not in seen}
    print(f"Fresh Indonesian organizations in ROR: {len(registry)}", flush=True)
    cached, _ = fresh_candidates(seen)
    account_candidates = [row for row in cached if row["site_key"] in registry]
    verified: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=40) as pool:
        futures = [pool.submit(verify, row) for row in account_candidates]
        for future in as_completed(futures):
            try:
                row = future.result()
            except Exception:
                continue
            if row:
                verified[row["site_key"]] = row
    print(f"Reverified account pages: {len(verified)}", flush=True)

    remaining = [item for key, item in registry.items() if key not in verified]
    with ThreadPoolExecutor(max_workers=80) as pool:
        for start in range(0, len(remaining), 400):
            if len(verified) >= 350:
                break
            batch = remaining[start:start + 400]
            futures = [pool.submit(verify_official_site, item) for item in batch]
            for future in as_completed(futures):
                try:
                    row = future.result()
                except Exception:
                    continue
                if row:
                    verified.setdefault(row["site_key"], row)
            print(f"Official sites checked: {start + len(batch)}; verified: {len(verified)}", flush=True)

    # Prefer account-like pages, then round-robin across Indonesian sectors.
    accounts = [row for row in verified.values() if row.get("auth_in_url") or row.get("password_input_in_html")]
    others = [row for row in verified.values() if row not in accounts]
    buckets: dict[str, list[dict]] = {}
    for row in sorted(accounts, key=lambda x: (x["sector"], x["site_key"])):
        buckets.setdefault(row["sector"], []).append(row)
    for row in sorted(others, key=lambda x: (x["sector"], x["site_key"])):
        buckets.setdefault(row["sector"], []).append(row)
    ordered = []
    while any(buckets.values()) and len(ordered) < 330:
        for sector in sorted(buckets):
            if buckets[sector]:
                ordered.append(buckets[sector].pop(0))
            if len(ordered) >= 330:
                break
    if len(ordered) < 300:
        raise RuntimeError(f"Only {len(ordered)} Indonesian sites passed HTTP preflight; no list released")
    selected, reserve = ordered[:300], ordered[300:]
    OUTPUT.write_text("\n".join(row["url"] for row in selected) + "\n", encoding="utf-8")
    RESERVE.write_text("\n".join(row["url"] for row in reserve) + ("\n" if reserve else ""), encoding="utf-8")
    fields = ["url", "final_url", "site_key", "title", "organization", "source_ror",
              "sector", "country", "auth_in_url", "password_input_in_html", "checked_at_utc"]
    with (BASE / "audit_300.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(selected)
    ext = HERE / "HeuriShield-URL18-XGBoost"
    tracked = ["manifest.json", "src/model/xgboost-url18.json",
               "src/analyzer/correlation/evidence-rules.js",
               "src/analyzer/correlation/decision-policy.js"]
    summary = {
        "prepared": len(selected), "reserve": len(reserve),
        "unique_domains": len({row["site_key"] for row in selected}),
        "country": "ID (ROR organization location)",
        "sectors": dict(Counter(row["sector"] for row in selected)),
        "account_paths": sum(bool(row.get("auth_in_url")) for row in selected),
        "password_inputs": sum(bool(row.get("password_input_in_html")) for row in selected),
        "source": "Official website links for Indonesian organizations in the ROR registry",
        "preflight": "HTTP 200 HTML, non-error title, same registrable site; extension analysis not guaranteed",
        "excluded_site_keys": len(seen), "exclusion_audit": exclusion_audit,
        "extension_version": json.loads((ext / "manifest.json").read_text(encoding="utf-8"))["version"],
        "extension_file_sha256": {name: hashlib.sha256((ext / name).read_bytes()).hexdigest()
                                  for name in tracked},
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    (BASE / "ringkasan.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
