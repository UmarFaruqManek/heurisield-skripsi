"""Combine per-URL results and freeze hashes for this evaluation run."""
import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EXT = ROOT.parent / "HeuriShield-URL18-XGBoost"
COHORTS = ("legitimate", "phishing", "targeted")
FIELDS = (
    "kelompok", "index", "input_url", "expected_label", "analysis_status",
    "site_http_status", "response_category", "redirect_category", "browser_final_url",
    "actual_verdict", "correct", "probability_phishing", "brand_identity_status",
    "source_domain_age_days", "no_analysis_reason", "page_title", "error"
)

rows = []
for cohort in COHORTS:
    with (ROOT / f"hasil_{cohort}" / "browser_live_rows.csv").open(encoding="utf-8-sig", newline="") as file:
        for row in csv.DictReader(file):
            rows.append({"kelompok": cohort, **{key: row.get(key, "") for key in FIELDS if key != "kelompok"}})
with (ROOT / "seluruh_url.csv").open("w", encoding="utf-8-sig", newline="") as file:
    writer = csv.DictWriter(file, fieldnames=FIELDS)
    writer.writeheader()
    writer.writerows(rows)

manifest_path = ROOT / "manifest.json"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
manifest["frozen_files_sha256"] = {}
for rel in ("manifest.json", "src/model/xgboost-url18.json",
            "src/analyzer/correlation/decision-policy.js",
            "src/content/dom-brand-observer.js"):
    file = EXT / rel
    manifest["frozen_files_sha256"][rel] = hashlib.sha256(file.read_bytes()).hexdigest()
manifest["evaluated_rows"] = len(rows)
manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
print(json.dumps({"rows": len(rows), "report": str(ROOT / "seluruh_url.csv")}, indent=2))
