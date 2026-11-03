r"""Ambil 300 situs unik secara acak dari Phishing Army domain-only feed.

Tidak membuat URL atau menilai model; domain perlu dipasangkan dengan URL
phishing yang benar-benar terverifikasi sebelum evaluasi XGBoost 18 fitur.
"""

from __future__ import annotations

import csv
import hashlib
import json
import random
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import tldextract


ROOT = Path(__file__).resolve().parent
SOURCE = Path(r"C:\Users\USER\Downloads\phishing-army-domains.txt")
OUT = ROOT / "persiapan_phishing_army_300"
DOMAIN_LIST = Path(r"C:\Users\USER\Downloads\phishing_army_domain_random_300_31okt.txt")
AUDIT = OUT / "audit_pemilihan_300.csv"
SUMMARY = OUT / "ringkasan.json"
CORPUS = ROOT / "gabungan_url_label_umur.csv"
PREVIOUS = ROOT / "hasil_uji_xgboost_300_phishing_100_legitimate" / "input_phishing_300.txt"
PARSER = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
SEED = 20261031
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$", re.I)
HARMLESS_TEST = {"amiprotected.it", "www.amiprotected.it"}


def site_key(hostname: str) -> str:
    ext = PARSER(hostname)
    return ext.top_domain_under_public_suffix or ""


def corpus_sites() -> set[str]:
    seen = set()
    with CORPUS.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            try:
                host = urlsplit(row["url"]).hostname or ""
                key = site_key(host)
                if key:
                    seen.add(key)
            except ValueError:
                continue
    if PREVIOUS.exists():
        for url in PREVIOUS.read_text(encoding="utf-8").splitlines():
            try:
                host = urlsplit(url.strip()).hostname or ""
                key = site_key(host)
                if key:
                    seen.add(key)
            except ValueError:
                continue
    return seen


def main():
    OUT.mkdir(exist_ok=True)
    for path in (DOMAIN_LIST, AUDIT, SUMMARY):
        if path.exists():
            raise FileExistsError(f"Tidak menimpa hasil sebelumnya: {path}")
    raw = SOURCE.read_bytes()
    lines = raw.decode("utf-8-sig", errors="replace").splitlines()
    comments = [line.strip() for line in lines if line.lstrip().startswith("#")]
    hosts = [line.strip().lower().rstrip(".") for line in lines
             if line.strip() and not line.lstrip().startswith("#")]
    seen = corpus_sites()
    grouped: dict[str, list[str]] = defaultdict(list)
    counts = Counter()
    for host in hosts:
        if host in HARMLESS_TEST:
            counts["harmless_test_excluded"] += 1
            continue
        if not DOMAIN_RE.fullmatch(host):
            counts["invalid_domain_excluded"] += 1
            continue
        site = site_key(host)
        if not site:
            counts["unknown_suffix_excluded"] += 1
            continue
        if site in seen:
            counts["historical_site_overlap_excluded"] += 1
            continue
        grouped[site].append(host)
    if len(grouped) < 300:
        raise ValueError(f"Hanya {len(grouped)} situs baru tersedia")

    rng = random.Random(SEED)
    sites = sorted(grouped)
    selected_sites = rng.sample(sites, 300)
    chosen = []
    for rank, site in enumerate(selected_sites, 1):
        host = rng.choice(sorted(set(grouped[site])))
        chosen.append({"rank": rank, "hostname": host, "site_key": site,
                       "hostname_candidates_in_site": len(grouped[site]),
                       "source": str(SOURCE)})
    with AUDIT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(chosen[0]))
        writer.writeheader()
        writer.writerows(chosen)
    DOMAIN_LIST.write_text("\n".join(row["hostname"] for row in chosen) + "\n", encoding="utf-8")

    summary = {
        "source": str(SOURCE), "source_sha256": hashlib.sha256(raw).hexdigest(),
        "selection_seed": SEED, "source_entries": len(hosts),
        "unique_hostnames": len(set(hosts)), "eligible_unique_sites": len(grouped),
        "selected_hostnames": len(chosen), "selected_unique_sites": len({row["site_key"] for row in chosen}),
        "excluded": dict(counts),
        "feed_generated": next((line for line in comments if line.startswith("# Generated:")), ""),
        "feed_expiry": next((line for line in comments if line.startswith("# Expires:")), ""),
        "prepared_at_utc": datetime.now(timezone.utc).isoformat(),
        "limitation": "Source is domain-only blocklist; no scheme/path or live page label. Do not calculate XGBoost accuracy from fabricated root URLs.",
    }
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
