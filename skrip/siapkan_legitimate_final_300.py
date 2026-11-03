"""Prepare fresh official account pages for the frozen URL18 extension evaluation.

The HTTP preflight is not an extension test; failures are kept out of the list.
"""
from __future__ import annotations

import csv
import hashlib
import json
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
from siapkan_100_legitimate_xgboost import site_key
from siapkan_legitimate_fresh_500_02nov import (
    AUTH_HARD, is_account_like, prior_sites,
)
from siapkan_legitimate_stratified_300 import (
    STRONG_TITLE, balanced_pick, inspect_website, registry_records,
)
from siapkan_legitimate_dual_300 import page

BASE = HERE / "data/input_uji/persiapan_legitimate_final_300_02nov2026"
BASE.mkdir(exist_ok=True)
OUTPUT = Path(r"C:\Users\USER\Downloads\legitimate_final_300_02nov2026.txt")
RESERVE = Path(r"C:\Users\USER\Downloads\legitimate_final_300_cadangan_02nov2026.txt")
SOURCES = [
    HERE / "data/input_uji/persiapan_legitimate_stratified_02nov2026" / "pemeriksaan_website.jsonl",
    HERE / "data/input_uji/persiapan_legitimate_fresh_500_02nov2026" / "pemeriksaan_website.jsonl",
]
CHECKPOINT = BASE / "pemeriksaan_tambahan.jsonl"


def fresh_candidates(seen: set[str]) -> tuple[list[dict], set[str]]:
    rows: dict[str, dict] = {}
    checked: set[str] = set()
    for path in [*SOURCES, CHECKPOINT]:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                item = json.loads(line)
                key = item["site_key"]
            except (ValueError, KeyError):
                continue
            checked.add(key)
            if key not in seen and item.get("result"):
                rows[key] = item["result"]
    return list(rows.values()), checked


def verify(item: dict) -> dict | None:
    response = page(item["url"])
    if not response or site_key(response[0]) != item["site_key"]:
        return None
    final, title, soup = response
    # A stale cached login cue is not enough if the current page changed.
    password = bool(soup.select('input[type="password"]'))
    auth_path = bool(AUTH_HARD.search(urlsplit(item["url"]).path))
    if not (password or auth_path or STRONG_TITLE.search(title)):
        return None
    return {**item, "final_url": final, "title": title,
            "password_input_in_html": password, "auth_in_url": auth_path,
            "checked_at_utc": datetime.now(timezone.utc).isoformat()}


def verify_official_site(item: dict) -> dict | None:
    """Use the ROR-listed site itself when no fresh account page is available."""
    url = item["source_url"].replace("http://", "https://", 1)
    response = page(url)
    if not response or site_key(response[0]) != item["site_key"]:
        return None
    final, title, soup = response
    return {**item, "url": final, "final_url": final, "title": title,
            "password_input_in_html": bool(soup.select('input[type="password"]')),
            "auth_in_url": bool(AUTH_HARD.search(urlsplit(final).path)),
            "checked_at_utc": datetime.now(timezone.utc).isoformat()}


def main() -> None:
    seen, exclusions = prior_sites()
    candidates, checked = fresh_candidates(seen)
    print(f"Fresh cached candidates: {len(candidates)}; excluded site keys: {len(seen)}", flush=True)
    verified: dict[str, dict] = {}

    def verify_batch(items: list[dict]) -> None:
        with ThreadPoolExecutor(max_workers=28) as pool:
            futures = [pool.submit(verify, item) for item in items]
            for future in as_completed(futures):
                try:
                    row = future.result()
                except Exception:
                    continue
                if row and row["site_key"] not in seen:
                    verified[row["site_key"]] = row

    verify_batch([row for row in candidates if is_account_like(row)])
    print(f"Reverified cached pages: {len(verified)}", flush=True)

    if len(verified) < 330:
        # A final test should include varied genuine sites; live-checking a ROR
        # homepage is much faster than searching for a login page on every site.
        source = registry_records(seen | checked | set(verified))
        with ThreadPoolExecutor(max_workers=80) as pool:
            for start in range(0, len(source), 400):
                if len(verified) >= 350 or start >= 4000:
                    break
                futures = [pool.submit(verify_official_site, item)
                           for item in source[start:start + 400]]
                for future in as_completed(futures):
                    try:
                        row = future.result()
                    except Exception:
                        continue
                    if row and row["site_key"] not in seen:
                        verified[row["site_key"]] = row
                print(f"Additional official sites checked: {start + len(futures)}; verified: {len(verified)}",
                      flush=True)

    ordered = balanced_pick(list(verified.values()), min(330, len(verified)))
    if len(ordered) < 300:
        raise RuntimeError(f"Only {len(ordered)} fresh pages passed preflight; no list released")
    selected, reserve = ordered[:300], ordered[300:]
    OUTPUT.write_text("\n".join(row["url"] for row in selected) + "\n", encoding="utf-8")
    RESERVE.write_text("\n".join(row["url"] for row in reserve) + ("\n" if reserve else ""),
                       encoding="utf-8")
    fields = ["url", "final_url", "site_key", "title", "organization", "source_ror",
              "sector", "country", "auth_in_url", "password_input_in_html", "checked_at_utc"]
    with (BASE / "audit_300.csv").open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(selected)
    extension = HERE / "extension/HeuriShield-URL18-XGBoost"
    tracked = ["manifest.json", "src/model/xgboost-url18.json",
               "src/analyzer/correlation/evidence-rules.js",
               "src/analyzer/correlation/decision-policy.js"]
    summary = {
        "prepared": len(selected), "reserve": len(reserve),
        "unique_sites": len({row["site_key"] for row in selected}),
        "sectors": dict(Counter(row["sector"] for row in selected)),
        "countries": len({row["country"] for row in selected}),
        "auth_paths": sum(bool(row["auth_in_url"]) for row in selected),
        "password_inputs": sum(bool(row["password_input_in_html"]) for row in selected),
        "source": "ROR official website links; account pages linked from those sites",
        "preflight": "HTTP 200 HTML, non-error title, same registrable site; extension analysis not guaranteed",
        "exclusions": exclusions,
        "extension_version": json.loads((extension / "manifest.json").read_text(encoding="utf-8"))["version"],
        "extension_file_sha256": {name: hashlib.sha256((extension / name).read_bytes()).hexdigest()
                                  for name in tracked},
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    (BASE / "ringkasan.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False),
                                         encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
