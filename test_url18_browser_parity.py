"""Compare Python and browser JavaScript extraction and XGBoost scores."""

import csv
import json
import random
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import tldextract

from ekstrak_fitur_url import URL_FEATURES, extract_url_features


ROOT = Path(__file__).resolve().parent
EXT = ROOT / "HeuriShield-URL18-XGBoost"
PUBLIC = tldextract.TLDExtract(suffix_list_urls=())


def main():
    source = ROOT / "DATA_URL_18_FITUR.csv"
    with source.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    random.Random(20261101).shuffle(rows)
    chosen = rows if "--all" in sys.argv else rows[:2000]
    # Include the new, previously evaluated legitimate URLs.
    with (ROOT / "kandidat_legitimate_baru_01nov/legitimate_fresh_300_subdomain_path_01nov.txt").open(encoding="utf-8") as handle:
        chosen += [{"url": url.strip(), "domain_age_days": ""} for url in handle if url.strip()]
    chosen += [{"url": url, "domain_age_days": "100"} for url in [
        "http://[::1]/a", "https://example.com:8443/a?b=2#f",
        "https://niƙe.com/login", "https://-test.pages.dev/verify-account",
        "https://kkn.uho.ac.id/login?next=%2F"
    ]]
    items = [{"url": row["url"], "age": float(row["domain_age_days"]) if row["domain_age_days"] else None}
             for row in chosen]
    result = subprocess.run(["node", str(EXT / "tests/parity-runner.mjs")], input=json.dumps(items),
                            capture_output=True, text=True, check=True)
    browser = json.loads(result.stdout)
    main_model = joblib.load(ROOT / "hasil_perbandingan_6_model/model/XGBoost.joblib")
    mismatches = []
    for item, js in zip(items, browser):
        py = extract_url_features(item["url"])
        host = (urlsplit(item["url"]).hostname or "").encode("idna").decode("ascii")
        domain = PUBLIC(host).top_domain_under_public_suffix or None
        if domain != js["domain"]:
            mismatches.append({"url": item["url"], "kind": "domain", "python": domain, "js": js["domain"]})
        for feature in URL_FEATURES:
            if py[feature] != js["features"][feature]:
                mismatches.append({"url": item["url"], "kind": feature,
                                   "python": py[feature], "js": js["features"][feature]})
        features = [py[name] for name in URL_FEATURES]
        features.append(np.nan if item["age"] is None else item["age"])
        expected = main_model.predict_proba(np.array([features], dtype=float))[0, 1]
        if abs(expected - js["probability"]) > 1e-5:
            mismatches.append({"url": item["url"], "kind": "probability",
                               "python": float(expected), "js": js["probability"]})
    report = {"urls": len(items), "features_per_url": len(URL_FEATURES),
              "mismatches": len(mismatches), "examples": mismatches[:30]}
    output = EXT / "tests/parity-report.json"
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=True))
    if mismatches:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
