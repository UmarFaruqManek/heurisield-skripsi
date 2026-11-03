"""Audit user PSL snapshot against the frozen training parser, without mutating features."""

import csv
import json
from pathlib import Path
from urllib.parse import urlsplit

import tldextract


ROOT = Path(__file__).resolve().parent
SNAPSHOT = ROOT.parent / "referensi_domain/public_suffix_list_2026-10-29.dat"
IANA = ROOT.parent / "referensi_domain/iana_tld_2026-10-29.txt"
TRAIN = ROOT / "DATA_URL_18_FITUR.csv"
OUT = ROOT / "HeuriShield-URL18-XGBoost/tests/tld-audit.json"


def main():
    bundled = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
    user_psl = tldextract.TLDExtract(suffix_list_urls=(SNAPSHOT.as_uri(),),
                                     fallback_to_snapshot=False, include_psl_private_domains=True)
    with TRAIN.open(encoding="utf-8") as handle:
        hosts = sorted({urlsplit(row["url"]).hostname for row in csv.DictReader(handle)})
    differences = []
    for host in hosts:
        old, new = bundled(host), user_psl(host)
        if old != new:
            differences.append({"host": host, "model_site": old.top_domain_under_public_suffix,
                                "snapshot_site": new.top_domain_under_public_suffix,
                                "model_subdomain": old.subdomain, "snapshot_subdomain": new.subdomain})
    tlds = {line.strip().lower() for line in IANA.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")}
    report = {"training_hosts": len(hosts), "snapshot_parser_differences": len(differences),
              "iana_tld_count": len(tlds), "examples": differences[:40],
              "decision": "Model feature values remain based on bundled tldextract PSL; user snapshot is audited only."}
    OUT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"{len(hosts)} hosts; {len(differences)} parser differences; {len(tlds)} IANA TLDs. Report: {OUT}")


if __name__ == "__main__":
    main()
