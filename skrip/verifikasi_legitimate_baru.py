"""Audit kandidat URL legitimate untuk uji URL saja; tidak menjalankan model."""

from __future__ import annotations

import csv
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd
import requests
import tldextract


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data/input_uji/kandidat_legitimate_baru_01nov"
DOWNLOADS = Path(r"C:\Users\USER\Downloads")
SITE = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
LOGIN = re.compile(r"login|log-in|signin|sign-in|account|verify|auth|secure|portal|password|registr", re.I)
EXCLUDED_PATH = re.compile(r"\.(pdf|jpe?g|png|webp|docx?|xlsx?|zip|css|js)$", re.I)
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; HeuriShieldResearch/1.0)"}


def site_key(url: str) -> str:
    host = urlsplit(url).hostname or ""
    return SITE(host).top_domain_under_public_suffix or host


def tested_sites() -> set[str]:
    seen = set(pd.read_csv(ROOT / "hasil/hasil_perbandingan_6_model" / "pembagian_data.csv", usecols=["site_key"]).site_key)
    for pattern in (
        "legitimate_fresh*.txt", "legitimate_baru*.txt", "legitimate_phishing_like*.txt",
        "legitimate_indonesia*.txt", "legitimate_300*.txt",
    ):
        for path in DOWNLOADS.glob(pattern):
            for url in re.findall(r"https?://[^\s<>\]\)]+", path.read_text(encoding="utf-8-sig", errors="ignore")):
                seen.add(site_key(url))
    for path in (ROOT / "data/input_uji/input_uji_legitimate_31okt").glob("*.txt"):
        for url in path.read_text(encoding="utf-8").splitlines():
            seen.add(site_key(url))
    return seen


def tranco_rank() -> dict[str, int]:
    with (DOWNLOADS / "tranco_L5PZ4.csv").open(encoding="utf-8", newline="") as file:
        return {row[1].lower(): int(row[0]) for row in csv.reader(file) if len(row) >= 2 and row[0].isdigit()}


def candidates():
    seen = tested_sites()
    rank = tranco_rank()
    pool = {}
    sources = [
        (OUT / "hasil_pencarian_web.txt", "web_search"),
        (DOWNLOADS / "legitimate_urls_2000_diverse.txt", "curated_2000"),
    ]
    for path, source in sources:
        for url in path.read_text(encoding="utf-8-sig", errors="ignore").splitlines():
            url = url.strip()
            parsed = urlsplit(url)
            host = parsed.hostname or ""
            site = SITE(host)
            key = site.top_domain_under_public_suffix or host
            if (
                parsed.scheme != "https" or not host or key in seen or key in pool
                or not site.subdomain or site.subdomain.lower() == "www"
                or parsed.path in ("", "/") or EXCLUDED_PATH.search(parsed.path)
            ):
                continue
            if source == "curated_2000" and rank.get(key, 9_999_999) > 1_000_000:
                continue
            pool[key] = {"url": url, "site": key, "source": source,
                         "tranco_rank": rank.get(key), "login_like": bool(LOGIN.search(url))}
    return sorted(pool.values(), key=lambda x: (not x["login_like"], x["source"] != "web_search", x["tranco_rank"] or 9_999_999))


def check(item):
    item = dict(item)
    try:
        response = requests.get(item["url"], headers=HEADERS, timeout=(5, 10),
                                allow_redirects=True, stream=True)
        item["http_status"] = response.status_code
        item["final_url"] = response.url
        item["final_site"] = site_key(response.url)
        item["content_type"] = response.headers.get("Content-Type", "").split(";", 1)[0]
        item["verified"] = (response.status_code == 200 and item["final_site"] == item["site"]
                            and (not item["content_type"] or "html" in item["content_type"]))
        response.close()
    except requests.RequestException as exc:
        item["http_status"] = type(exc).__name__
        item["final_url"] = ""
        item["final_site"] = ""
        item["content_type"] = ""
        item["verified"] = False
    return item


def main():
    OUT.mkdir(exist_ok=True)
    pool = candidates()
    print(f"Candidates {len(pool)}; login_like {sum(item['login_like'] for item in pool)}", flush=True)
    results = []
    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = [executor.submit(check, item) for item in pool]
        for i, future in enumerate(as_completed(futures), 1):
            results.append(future.result())
            if i % 50 == 0:
                print(f"Checked {i}/{len(pool)}; verified {sum(item['verified'] for item in results)}", flush=True)
    results.sort(key=lambda x: (not x["verified"], not x["login_like"], x["source"] != "web_search", x["tranco_rank"] or 9_999_999))
    with (OUT / "audit_http.csv").open("w", encoding="utf-8-sig", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(results[0]))
        writer.writeheader()
        writer.writerows(results)
    report = {"candidates": len(pool), "verified_http_200_same_site": sum(item["verified"] for item in results),
              "verified_login_like": sum(item["verified"] and item["login_like"] for item in results)}
    (OUT / "ringkasan_verifikasi.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report), flush=True)


if __name__ == "__main__":
    main()
