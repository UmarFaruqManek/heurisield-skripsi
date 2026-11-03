"""Kumpulkan 300 URL legitimate baru dengan halaman HTML dan umur domain tersedia.

Sumber domain: situs resmi pada catatan ROR. Pemeriksaan dilakukan tanpa model
agar daftar ini tetap dapat dipakai sebagai uji independen berikutnya.
"""

from __future__ import annotations

import asyncio
import csv
import json
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from siapkan_100_legitimate_xgboost import (
    ROOT, candidates, excluded_sites, load_helpers, site_key, verify_all,
)
from uji_xgboost_300_phishing_100_legitimate import (
    PHISH_SOURCE, PUBLIC, domain, lookup_age, read_urls, registry_map,
)

OUT = ROOT / "persiapan_300_legitimate_xgboost"
LIST = Path(r"C:\Users\USER\Downloads\legitimate_baru_300_xgboost_terverifikasi_31okt.txt")
VERIFIED = OUT / "verified_pages.jsonl"
AGES = OUT / "domain_age_rdap.jsonl"
AUDIT = OUT / "audit_300_terverifikasi.csv"
SUMMARY = OUT / "ringkasan_terverifikasi.json"
BAD_PAGE = re.compile(
    r"bluehost|web server.s default page|domain.{0,30}for sale|"
    r"parked domain|account suspended|site not found|under construction|"
    r"coming soon|default web site page|this domain is available|"
    r"checking your browser|redirecting|verify you are human", re.I
)


def read_jsonl(path):
    records = []
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                records.append(json.loads(line))
            except ValueError:
                continue
    return records


def main():
    OUT.mkdir(exist_ok=True)
    if LIST.exists() or AUDIT.exists() or SUMMARY.exists():
        raise FileExistsError("Hasil final sudah tersedia; tidak menimpa daftar lama")
    helper = load_helpers()
    seen = excluded_sites(helper)
    phish_sites = {site_key(url) for url in read_urls(PHISH_SOURCE)}
    items = [item for item in candidates(helper.ror_orgs(), seen, helper)
             if item["site_key"] not in phish_sites]
    print(f"Kandidat domain baru: {len(items)}", flush=True)

    checked = set()
    verified = read_jsonl(VERIFIED)
    verified_sites = {row["site_key"] for row in verified}
    # Periksa secara bertahap; checkpoint bertahan bila proses terhenti.
    for start in range(0, min(len(items), 2200), 200):
        if len(verified) >= 500:
            break
        batch = [item for item in items[start:start + 200] if item["site_key"] not in verified_sites]
        if not batch:
            continue
        results = asyncio.run(verify_all(batch))
        filtered = [row for row in results if not BAD_PAGE.search(row.get("title") or "")]
        with VERIFIED.open("a", encoding="utf-8") as handle:
            for row in filtered:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        verified.extend(filtered)
        verified_sites.update(row["site_key"] for row in filtered)
        print(f"Halaman {min(start + 200, len(items))}/{min(len(items), 2200)}; terverifikasi={len(verified)}", flush=True)
        if len(verified) >= 500:
            break

    # Cari umur domain hanya setelah URL dan halaman lolos pemeriksaan.
    age_cache = {row["domain"]: row for row in read_jsonl(AGES)}
    domains = sorted({domain(row["url"], PUBLIC) for row in verified})
    missing = [name for name in domains if name not in age_cache]
    print(f"RDAP untuk {len(missing)} domain baru dari {len(domains)} domain", flush=True)
    servers = registry_map()
    with AGES.open("a", encoding="utf-8") as handle, ThreadPoolExecutor(max_workers=3) as pool:
        pending = []
        for name in missing:
            pending.append(pool.submit(lookup_age, name, servers))
            time.sleep(0.25)
        for index, future in enumerate(as_completed(pending), 1):
            result = future.result()
            age_cache[result["domain"]] = result
            handle.write(json.dumps(result, ensure_ascii=False) + "\n")
            handle.flush()
            if index % 100 == 0:
                print(f"RDAP {index}/{len(missing)}", flush=True)

    eligible = []
    used_sites = set()
    for row in verified:
        site = row["site_key"]
        if site in used_sites:
            continue
        if not str(row.get("title") or "").strip():
            continue
        title = str(row["title"]).strip().lower()
        host = (urlsplit(row["url"]).hostname or "").lower()
        if BAD_PAGE.search(title) or title in {host, host.removeprefix("www.")}:
            continue
        age = age_cache.get(domain(row["url"], PUBLIC), {})
        if age.get("status") != "found":
            continue
        used_sites.add(site)
        eligible.append({**row, "domain_age_days": age["age_days"],
                         "registration_date": age["registered_at"],
                         "age_provider": age.get("provider", "")})

    # Urutan acak tetap agar tidak memilih berdasarkan prediksi atau label model.
    import random
    random.Random(20261031).shuffle(eligible)
    selected = eligible[:300]
    if len(selected) < 300:
        print(f"Hanya {len(selected)} URL memenuhi seluruh syarat; tidak mengarang URL.", flush=True)
    with AUDIT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(selected[0]) if selected else ["url"])
        writer.writeheader()
        writer.writerows(selected)
    LIST.write_text("\n".join(row["url"] for row in selected) + "\n", encoding="utf-8")
    summary = {"target": 300, "selected": len(selected), "checked_at_utc": datetime.now(timezone.utc).isoformat(),
               "ror_candidate_sites": len(items), "html_200_sites": len(verified),
               "age_available_sites": len(eligible), "unique_sites": len({row["site_key"] for row in selected}),
               "https": sum(urlsplit(row["url"]).scheme == "https" for row in selected),
               "http": sum(urlsplit(row["url"]).scheme == "http" for row in selected),
               "path_urls": sum(bool(urlsplit(row["url"]).path.strip("/")) for row in selected),
               "tlds": dict(Counter(row["tld"] for row in selected)),
               "status": "HTTP 200 HTML and RDAP age available at preparation time; browser live status not guaranteed"}
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
