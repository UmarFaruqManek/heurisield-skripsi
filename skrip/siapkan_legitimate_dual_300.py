"""Siapkan 300 URL legitimate baru untuk dua extension, tanpa menjalankan uji live.

Identitas organisasi/situs berasal dari ROR. Link halaman harus ditemukan pada
situs itu sendiri, merespons HTML 200, dan tidak ada domainnya di data lama.
"""
from __future__ import annotations

import csv
import json
import random
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from siapkan_100_legitimate_xgboost import candidates, excluded_sites, load_helpers, site_key  # noqa: E402

OUTPUT = Path(r"C:\Users\USER\Downloads\legitimate_fresh_dual_300_01nov2026.txt")
AUDIT_DIR = ROOT / "data/input_uji/persiapan_legitimate_dual_01nov2026"
CHECKPOINT = AUDIT_DIR / "hasil_pemeriksaan.jsonl"
AUDIT = AUDIT_DIR / "audit_300.csv"
SUMMARY = AUDIT_DIR / "ringkasan.json"

HARD = re.compile(r"login|log.?in|sign.?in|account|password|auth|portal|register|reset|recover|verify|security|payment|billing|identity|masuk|pendaftaran|sso", re.I)
AUTH = re.compile(r"(?<![a-z])(?:login|log-in|signin|sign-in|account|accounts|password|auth|oauth|portal|register|registration|reset|recover|verify|verification|payment|billing|identity|masuk|pendaftaran|sso)(?![a-z])", re.I)
SOFT = re.compile(r"service|support|help|student|admission|apply|library|dashboard|profile|faculty|directory|contact|program|layanan", re.I)
BAD = re.compile(r"(?:404|not found|page not found|access denied|service unavailable|captcha|just a moment|checking your browser|site can't be reached|domain for sale|under construction)", re.I)
ASSET = re.compile(r"\.(?:pdf|docx?|xlsx?|zip|png|jpe?g|gif|svg|webp|css|js|json|xml|mp4|woff2?)(?:$|\?)", re.I)
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130 Safari/537.36"}


def clean_url(raw: str) -> str | None:
    try:
        p = urlsplit(raw)
        if p.scheme != "https" or not p.hostname or p.username or p.password:
            return None
        if ASSET.search(p.path):
            return None
        path = p.path or "/"
        if len([x for x in path.split("/") if x]) > 4:
            return None
        return urlunsplit((p.scheme, p.netloc.lower(), path, "", ""))
    except ValueError:
        return None


def page(url: str):
    try:
        response = requests.get(url, headers=HEADERS, timeout=(4, 9), allow_redirects=True)
        if response.status_code != 200 or "html" not in response.headers.get("content-type", "").lower():
            return None
        final = clean_url(response.url)
        if not final or site_key(final) != site_key(url):
            return None
        soup = BeautifulSoup(response.content[:600_000], "html.parser")
        title = soup.title.get_text(" ", strip=True)[:180] if soup.title else ""
        if not title or BAD.search(title):
            return None
        for tag in soup(["script", "style", "noscript", "svg"]):
            tag.decompose()
        if len(soup.get_text(" ", strip=True)) < 120:
            return None
        return final, title, soup
    except (requests.RequestException, ValueError, UnicodeError):
        return None


def check_org(item: dict) -> dict | None:
    base = page(item["source_url"].replace("http://", "https://", 1))
    if not base:
        return None
    homepage, _, soup = base
    if site_key(homepage) != item["site_key"]:
        return None
    links: dict[str, tuple[int, str]] = {}
    for tag in soup.select("a[href]"):
        link = clean_url(urljoin(homepage, tag.get("href", "")))
        if not link or site_key(link) != item["site_key"]:
            continue
        p = urlsplit(link)
        if p.path in ("", "/"):
            continue
        text = tag.get_text(" ", strip=True)[:80]
        sample = link + " " + text
        score = 150 if AUTH.search(sample) else 100 if HARD.search(sample) else 30 if SOFT.search(sample) else 0
        if not score:
            continue
        if p.hostname and not p.hostname.startswith("www.") and p.hostname != item["site_key"]:
            score += 5
        old = links.get(link)
        if not old or score > old[0]:
            links[link] = (score, text)
    for link, (score, text) in sorted(links.items(), key=lambda x: (-x[1][0], len(x[0])))[:4]:
        checked = page(link)
        if checked and site_key(checked[0]) == item["site_key"]:
            return {"url": link, "final_url": checked[0], "title": checked[1],
                    "score": score, "link_text": text, "source_homepage": homepage,
                    "source_ror": item["source_ror"], "organization": item["organization"],
                    "site_key": item["site_key"], "checked_at_utc": datetime.now(timezone.utc).isoformat(),
                    "http_status": 200}
    return None


def main():
    AUDIT_DIR.mkdir(exist_ok=True)
    helper = load_helpers()
    seen = excluded_sites(helper)
    # This script can resume and refine an already prepared file. That file
    # must not count as a historical test, otherwise its own 300 sites vanish.
    if OUTPUT.exists():
        prepared = {site_key(url.strip()) for url in OUTPUT.read_text(encoding="utf-8").splitlines() if url.strip()}
        seen.difference_update(prepared)
    # Exclude both labels from historical browser runs, including recent runs
    # stored outside the model's train/test corpus.
    for folder in [Path(r"D:\Deployment Extension\data\evaluasi_live"), ROOT / "hasil/hasil_live_dual_01nov2026"]:
        if not folder.exists():
            continue
        for path in folder.rglob("browser_live_rows.csv"):
            with path.open(encoding="utf-8-sig", errors="ignore", newline="") as stream:
                for row in csv.DictReader(stream):
                    for key in ("input_url", "final_url", "browser_final_url"):
                        if row.get(key):
                            seen.add(site_key(row[key]))
    items = candidates(helper.ror_orgs(), seen, helper)
    random.Random(20261101).shuffle(items)
    completed = {}
    if CHECKPOINT.exists():
        for line in CHECKPOINT.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
                completed[row["site_key"]] = row
            except (ValueError, KeyError):
                continue
    found = [row["result"] for row in completed.values() if row.get("result")]
    print(f"ROR candidates={len(items)}, excluded_domains={len(seen)}, resumed={len(completed)}, valid={len(found)}", flush=True)
    with ThreadPoolExecutor(max_workers=48) as pool, CHECKPOINT.open("a", encoding="utf-8") as log:
        # Batches avoid launching thousands of pending requests once enough URL are found.
        for start in range(0, len(items), 120):
            if len(found) >= 850:
                break
            batch = [item for item in items[start:start + 120] if item["site_key"] not in completed]
            futures = {pool.submit(check_org, item): item for item in batch}
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
                if result:
                    found.append(result)
            print(f"checked={len(completed)}/{len(items)}, valid={len(found)}", flush=True)

    unique = {}
    for row in found:
        if row["site_key"] not in seen:
            unique.setdefault(row["site_key"], row)
    selected = sorted(unique.values(), key=lambda x: (
        not bool(AUTH.search(x["url"])),
        not bool(AUTH.search(x["url"] + " " + x["link_text"])),
        -x["score"], x["site_key"]))[:300]
    if len(selected) < 300:
        print(f"Only {len(selected)} valid URLs; no fabricated or unverified URLs will be added.", flush=True)
    with AUDIT.open("w", encoding="utf-8-sig", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["url", "final_url", "site_key", "title", "score", "link_text", "source_homepage", "source_ror", "organization", "http_status", "checked_at_utc"])
        writer.writeheader()
        writer.writerows(selected)
    OUTPUT.write_text("\n".join(row["url"] for row in selected) + "\n", encoding="utf-8")
    summary = {"target": 300, "selected": len(selected), "unique_domains": len({x["site_key"] for x in selected}),
               "login_like": sum(bool(HARD.search(x["url"] + " " + x["link_text"])) for x in selected),
               "auth_url_pattern": sum(bool(AUTH.search(x["url"])) for x in selected),
               "checked_at_utc": datetime.now(timezone.utc).isoformat(), "candidate_source": "ROR website record",
               "note": "HTTP 200 HTML at preparation time; browser analysis and current label must be checked during live test."}
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
