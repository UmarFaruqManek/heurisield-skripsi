"""Prepare new, verified, account-like legitimate URLs for live testing.

Uses official organization website links from the locally cached ROR data.
No extension test is run here.
"""
from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from openpyxl import load_workbook

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from siapkan_100_legitimate_xgboost import excluded_sites, load_helpers, site_key
from siapkan_legitimate_stratified_300 import (
    STRONG_TITLE, balanced_pick, inspect_website, registry_records,
)

BASE = HERE / "data/input_uji/persiapan_legitimate_fresh_500_02nov2026"
BASE.mkdir(exist_ok=True)
PREVIOUS_CHECKPOINT = HERE / "data/input_uji/persiapan_legitimate_stratified_02nov2026" / "pemeriksaan_website.jsonl"
CHECKPOINT = BASE / "pemeriksaan_website.jsonl"
OUTPUT = Path(r"C:\Users\USER\Downloads\legitimate_fresh_500_02nov2026.txt")
AUDIT = BASE / "audit_500.csv"
SUMMARY = BASE / "ringkasan.json"
AUTH_HARD = re.compile(r"(?<![a-z])(?:login|log-in|logon|sign-in|signin|account|accounts|password|forgot|reset|recover|verify|verification|register|registration|sign-up|signup|portal|dashboard|sso|oauth|mfa|2fa|billing|payment|identity)(?![a-z])", re.I)


def is_account_like(row: dict) -> bool:
    return bool(AUTH_HARD.search(urlsplit(row["url"]).path) or
                row["password_input_in_html"] or STRONG_TITLE.search(row["title"]))


def prior_sites() -> tuple[set[str], dict]:
    helper = load_helpers()
    sites = excluded_sites(helper)
    counts = {"existing_lists_and_main_training": len(sites)}
    roots = [Path(r"D:\experimen"), Path(r"D:\Deployment Extension\data")]
    csv_count = 0
    for root in roots:
        for path in root.rglob("*.csv"):
            if path == AUDIT:
                continue
            try:
                with path.open(encoding="utf-8-sig", errors="ignore", newline="") as stream:
                    reader = csv.DictReader(stream)
                    fields = reader.fieldnames or []
                    url_fields = [key for key in fields if key and (key.lower() in
                                  {"url", "input_url", "final_url", "analysis_url", "browser_final_url", "analysis_final_url", "source_url"})]
                    if not url_fields:
                        continue
                    csv_count += 1
                    for row in reader:
                        for key in url_fields:
                            url = row.get(key)
                            if url and url.startswith(("https://", "http://")):
                                sites.add(site_key(url))
                                sites.add(helper.reg(url))
            except (OSError, UnicodeError, csv.Error):
                continue
    counts["csv_files_with_url_scanned"] = csv_count
    workbook = Path(r"D:\Deployment Extension\testing live extension\Riwayat_Testing_Live.xlsx")
    if workbook.exists():
        book = load_workbook(workbook, read_only=True, data_only=True)
        for sheet in book:
            for row in sheet.values:
                if row and isinstance(row[0], str) and row[0].startswith(("https://", "http://")):
                    sites.add(site_key(row[0]))
                    sites.add(helper.reg(row[0]))
        book.close()
    sites.discard("")
    counts["excluded_site_keys"] = len(sites)
    return sites, counts


def load_checkpoints() -> dict[str, dict]:
    completed = {}
    for path in (PREVIOUS_CHECKPOINT, CHECKPOINT):
        if not path.exists():
            continue
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                try:
                    row = json.loads(line)
                    completed[row["site_key"]] = row
                except (ValueError, KeyError):
                    continue
    return completed


def verify_again(item: dict) -> dict | None:
    """Recheck old candidates just before release; keep same-site HTML pages."""
    from siapkan_legitimate_dual_300 import page
    response = page(item["url"])
    if not response or site_key(response[0]) != item["site_key"]:
        return None
    final, _, soup = response
    title = soup.title.get_text(" ", strip=True)[:180] if soup.title else ""
    if not title:
        return None
    item = dict(item)
    item["final_url"] = final
    item["title"] = title
    item["checked_at_utc"] = datetime.now(timezone.utc).isoformat()
    return item


def main() -> None:
    seen, exclusion_counts = prior_sites()
    # Rebuilding this same generated list is safe; keep its already audited sites
    # eligible while all historical training and test sites remain excluded.
    if OUTPUT.exists():
        seen.difference_update(site_key(url.strip()) for url in
                               OUTPUT.read_text(encoding="utf-8").splitlines() if url.strip())
    completed = load_checkpoints()
    found = {key: row["result"] for key, row in completed.items()
             if row.get("result") and key not in seen}
    candidates = registry_records(seen)
    print(json.dumps({"candidates": len(candidates), "checked": len(completed),
                      "reusable_candidates": len(found), **exclusion_counts}), flush=True)
    # Collect reserves because some cached pages can disappear before final verification.
    with ThreadPoolExecutor(max_workers=36) as pool, CHECKPOINT.open("a", encoding="utf-8") as log:
        for start in range(0, len(candidates), 120):
            if len(found) >= 900:
                break
            batch = [item for item in candidates[start:start + 120]
                     if item["site_key"] not in completed]
            futures = {pool.submit(inspect_website, item): item for item in batch}
            for future in as_completed(futures):
                item = futures[future]
                try:
                    result = future.result()
                except Exception:
                    result = None
                row = {"site_key": item["site_key"], "result": result}
                completed[item["site_key"]] = row
                log.write(json.dumps(row, ensure_ascii=False) + "\n")
                log.flush()
                if result and item["site_key"] not in seen:
                    found[item["site_key"]] = result
            print(f"checked={len(completed)} valid_fresh={len(found)}", flush=True)
    account_like = [row for row in found.values() if is_account_like(row)]
    ordered = balanced_pick(account_like, min(len(account_like), 900))
    # Reverify selected candidates concurrently, not just their original homepages.
    verified = []
    with ThreadPoolExecutor(max_workers=28) as pool:
        for result in pool.map(verify_again, ordered):
            if result and is_account_like(result):
                verified.append(result)
    selected = balanced_pick(verified, 500)
    if len(selected) < 500:
        raise RuntimeError(f"Only {len(selected)} URLs verified; output not created")
    fields = ["url", "final_url", "site_key", "title", "link_text", "organization", "source_ror",
              "source_url", "sector", "country", "continent", "auth_in_url",
              "password_input_in_html", "page_cue", "http_status", "checked_at_utc"]
    with AUDIT.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(selected)
    OUTPUT.write_text("\n".join(row["url"] for row in selected) + "\n", encoding="utf-8")
    summary = {"requested": 500, "prepared": len(selected),
               "unique_sites": len({row["site_key"] for row in selected}),
               "sector_counts": dict(Counter(row["sector"] for row in selected)),
               "country_count": len({row["country"] for row in selected}),
               "auth_path_count": sum(bool(row["auth_in_url"]) for row in selected),
               "password_input_in_html": sum(bool(row["password_input_in_html"]) for row in selected),
               "strong_title_or_password": sum(bool(row["password_input_in_html"] or
                                               STRONG_TITLE.search(row["title"])) for row in selected),
               "excluded_site_key_count": len(seen), "exclusion_audit": exclusion_counts,
               "checked_at_utc": datetime.now(timezone.utc).isoformat(),
               "scope": "HTTP preflight on official ROR website links; browser extension completion not guaranteed"}
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
