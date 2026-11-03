"""Temukan kandidat URL resmi dari hasil pencarian untuk audit manual dan uji URL saja."""

from __future__ import annotations

import base64
import csv
import json
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pandas as pd
import requests
import tldextract
from bs4 import BeautifulSoup


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data/input_uji/kandidat_legitimate_baru_01nov"
SITE = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; HeuriShieldResearch/1.0)"}

SEARCHES = [
    'site:ac.id "login" "mahasiswa"',
    'site:ac.id "sign in" "mahasiswa"',
    'site:ac.id "portal" "login"',
    'site:ac.id "sso" "login"',
    'site:ac.id "akun" "login"',
    'site:ac.id "siakad" "login"',
    'site:ac.id "mfa" "login"',
    'site:go.id "login" "akun"',
    'site:go.id "login" "layanan"',
    'site:go.id "sso" "login"',
    'site:go.id "registrasi" "akun"',
    'site:sch.id "login" "siswa"',
    'site:or.id "login" "anggota"',
    'site:co.id "login" "akun"',
    'site:co.id "masuk" "akun"',
    'site:edu "login" "student"',
    'site:edu "account" "sign in"',
    'site:edu "sso" "login"',
    'site:edu "password reset"',
    'site:edu "mfa" "verify"',
    'site:gov "login" "account"',
    'site:gov "sign in" "portal"',
    'site:gov "verify" "account"',
    'site:gov.uk "sign in" "account"',
    'site:gov.au "login" "account"',
    'site:gov.sg "login" "account"',
    'site:gov.my "login" "account"',
    'site:ac.uk "login" "student"',
    'site:ac.uk "sso" "login"',
    'site:edu.au "login" "student"',
    'site:edu.my "login" "student"',
    'site:edu.sg "login" "student"',
    'site:edu.ph "login" "student"',
    'site:org "member" "login"',
    'site:org "account" "sign in"',
    'site:org "donor" "login"',
    'site:com "account" "login" "support"',
    'site:com "mfa" "sign in"',
    'site:com "secure" "account" "login"',
    'site:com "verify" "account"',
    'site:net "login" "account"',
    'site:io "login" "account"',
    'site:app "login" "account"',
]


def decode_bing(href: str) -> str:
    value = parse_qs(urlsplit(href).query).get("u", [""])[0]
    if value.startswith("a1"):
        try:
            return base64.b64decode(value[2:] + "===").decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return ""
    return href if href.startswith("https://") else ""


def search(query: str, first: int):
    try:
        response = requests.get(
            "https://www.bing.com/search",
            params={"q": query, "count": 50, "first": first, "setlang": "en-US"},
            headers=HEADERS,
            timeout=20,
        )
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        out = []
        for result in soup.select(".b_algo"):
            link = result.select_one("h2 a")
            if link is None:
                continue
            url = decode_bing(link.get("href", ""))
            if url:
                out.append((url, query, link.get_text(" ", strip=True)))
        return out
    except requests.RequestException:
        return []


def historic_sites() -> set[str]:
    split = pd.read_csv(ROOT / "hasil/hasil_perbandingan_6_model" / "pembagian_data.csv", usecols=["site_key"])
    seen = set(split.site_key.dropna().astype(str))
    files = list(Path(r"C:\Users\USER\Downloads").glob("*legitimate*.txt"))
    files += list(ROOT.glob("**/*legitimate*.txt"))
    for path in files:
        try:
            text = path.read_text(encoding="utf-8-sig", errors="ignore")
        except OSError:
            continue
        for raw in re.findall(r"https?://[^\s<>\]\)]+", text):
            host = urlsplit(raw).hostname
            if host:
                seen.add(SITE(host).top_domain_under_public_suffix or host)
    return seen


def main():
    OUT.mkdir(exist_ok=True)
    seen = historic_sites()
    tasks = [(query, first) for query in SEARCHES for first in (1, 11, 21, 31)]
    raw = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(search, *task) for task in tasks]
        for i, future in enumerate(as_completed(futures), 1):
            raw.extend(future.result())
            if i % 25 == 0:
                print(f"search {i}/{len(tasks)}; raw={len(raw)}", flush=True)
    unique = {}
    for url, query, title in raw:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        if parsed.scheme != "https" or not host:
            continue
        extracted = SITE(host)
        domain = extracted.top_domain_under_public_suffix or host
        if domain in seen or domain in unique:
            continue
        subdomain = bool(extracted.subdomain and extracted.subdomain.lower() != "www")
        path = parsed.path
        if not subdomain or path in ("", "/"):
            continue
        if re.search(r"\.(pdf|jpg|png|webp|docx?|xlsx?|css|js)$", path, re.I):
            continue
        unique[domain] = {"url": url, "domain": domain, "subdomain": extracted.subdomain,
                          "path": path, "query": query, "title": title}
    with (OUT / "kandidat_pencarian.csv").open("w", encoding="utf-8-sig", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["url", "domain", "subdomain", "path", "query", "title"])
        writer.writeheader()
        writer.writerows(unique.values())
    print(json.dumps({"searches": len(tasks), "raw": len(raw), "new_unique_sites_with_subdomain_and_path": len(unique), "out": str(OUT)}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
