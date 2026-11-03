"""Pilih 100 URL situs resmi ROR yang belum tercatat untuk uji live XGBoost."""
from __future__ import annotations

import asyncio
import csv
import importlib.util
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import tldextract

ROOT = Path(__file__).resolve().parent
OUTPUT = Path(r"C:\Users\USER\Downloads\legitimate_baru_100_uji_xgboost_31okt.txt")
AUDIT = ROOT / "audit_legitimate_baru_100_uji_xgboost.csv"
SUMMARY = ROOT / "ringkasan_legitimate_baru_100_uji_xgboost.json"
PARSER = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)


def site_key(url):
    host = urlsplit(url).hostname or ""
    return PARSER(host).top_domain_under_public_suffix or host


def load_helpers():
    path = Path(r"D:\Deployment Extension\Skrip\siapkan_legitimate_500_31okt.py")
    spec = importlib.util.spec_from_file_location("legitimate_helpers", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def excluded_sites(helper):
    seen = set(helper.exclusions())
    with (ROOT / "gabungan_url_label_umur.csv").open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            url = row.get("url", "")
            if url:
                seen.add(site_key(url))
                seen.add(helper.reg(url))
    return seen


def candidates(organizations, seen, helper):
    unique = {}
    for org in organizations:
        if org.get("status") != "active":
            continue
        for link in org.get("links", []):
            if link.get("type") != "website":
                continue
            url = link.get("value", "")
            if not url.startswith(("https://", "http://")):
                continue
            domain, site = helper.reg(url), site_key(url)
            if not domain or domain in seen or site in seen:
                continue
            name = next((n.get("value", "") for n in org.get("names", []) if "ror_display" in n.get("types", [])), "")
            unique.setdefault(site, {"source_url": url, "source_ror": org.get("id", ""),
                                     "organization": name, "site_key": site})
    return list(unique.values())


async def verify(client, item, semaphore):
    async with semaphore:
        try:
            response = await client.get(item["source_url"])
            url = str(response.url)
            if response.status_code != 200 or "html" not in response.headers.get("content-type", "").lower():
                return None
            if site_key(url) != item["site_key"]:
                return None
            sample = response.text[:30000]
            title_match = re.search(r"<title[^>]*>(.*?)</title>", sample, re.I | re.S)
            title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""
            if re.search(r"404|not found|access denied|service unavailable|captcha|just a moment", title, re.I):
                return None
            if len(re.sub(r"<[^>]+>", " ", sample).strip()) < 100:
                return None
            return {**item, "url": url, "http_status": 200, "title": title[:180],
                    "checked_at_utc": datetime.now(timezone.utc).isoformat(),
                    "redirect_count": len(response.history),
                    "tld": PARSER(urlsplit(url).hostname or "").suffix}
        except (httpx.HTTPError, ValueError, UnicodeError):
            return None


async def verify_all(items):
    timeout = httpx.Timeout(9.0, connect=5.0)
    limits = httpx.Limits(max_connections=36, max_keepalive_connections=18)
    async with httpx.AsyncClient(headers={"User-Agent": "Mozilla/5.0"}, follow_redirects=True,
                                 timeout=timeout, limits=limits) as client:
        semaphore = asyncio.Semaphore(36)
        results = await asyncio.gather(*(verify(client, item, semaphore) for item in items))
        return [result for result in results if result]


def main():
    for path in (OUTPUT, AUDIT, SUMMARY):
        if path.exists():
            raise FileExistsError(f"Tidak menimpa hasil sebelumnya: {path}")
    helper = load_helpers()
    seen = excluded_sites(helper)
    items = candidates(helper.ror_orgs(), seen, helper)[:700]
    print(f"Situs organisasi resmi yang belum tercatat: {len(items)}", flush=True)
    verified = asyncio.run(verify_all(items))
    print(f"Situs yang merespons HTML 200: {len(verified)}", flush=True)
    verified.sort(key=lambda item: (not bool(re.search(r"login|sign.?in|account|auth|portal|register|security|payment|sso|masuk", item["url"], re.I)),
                                    not bool(urlsplit(item["url"]).path.strip("/")), item["site_key"]))
    selected = verified[:100]
    if len(selected) < 100:
        print(f"Hanya {len(selected)} URL lolos verifikasi; tidak membuat URL rekaan.", flush=True)
    with AUDIT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(selected[0]) if selected else ["url"])
        writer.writeheader()
        writer.writerows(selected)
    OUTPUT.write_text("\n".join(item["url"] for item in selected) + "\n", encoding="utf-8")
    summary = {"target": 100, "selected": len(selected), "verified": len(verified),
               "candidates": len(items), "unique_sites": len({item["site_key"] for item in selected}),
               "tlds": dict(Counter(item["tld"] for item in selected)),
               "path_urls": sum(bool(urlsplit(item["url"]).path.strip("/")) for item in selected),
               "note": "Status HTTP 200 saat penyusunan; cek ulang di browser saat pengujian. XGBoost belum terpasang di extension."}
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
