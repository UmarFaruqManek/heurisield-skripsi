"""Select fresh, account-like legitimate URLs from official ROR website links.

This only checks HTTP pages and historical-domain overlap. It never launches
either HeuriShield extension or claims that browser analysis will complete.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import random
import re
import sys
import zipfile
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from siapkan_100_legitimate_xgboost import excluded_sites, load_helpers, site_key  # noqa: E402
from siapkan_legitimate_dual_300 import clean_url, page, BAD  # noqa: E402

BASE = ROOT / "data/input_uji/persiapan_legitimate_stratified_02nov2026"
SOURCE = BASE / "v2.15-2026-10-20-ror-data.zip"
CHECKPOINT = BASE / "pemeriksaan_website.jsonl"
OUTPUT = Path(r"C:\Users\USER\Downloads\legitimate_fresh_stratified_300_02nov2026.txt")
AUDIT = BASE / "audit_300.csv"
SUMMARY = BASE / "ringkasan.json"
AUTH = re.compile(r"(?<![a-z])(?:login|log-in|logon|sign-in|signin|account|accounts|my-account|password|forgot|reset|recover|verify|verification|register|registration|sign-up|signup|portal|dashboard|sso|oauth|mfa|2fa|billing|payment|identity|user|users|member|members|masuk|daftar)(?![a-z])", re.I)
HELP = re.compile(r"(?<![a-z])(?:support|help|security|service|layanan|bantuan)(?![a-z])", re.I)
EXCLUDE_PATH = re.compile(r"(?<![a-z])(?:blog|news|article|author|press|event|research|publication|policy|policies|about|contact)(?![a-z])", re.I)
PAGE_CUE = re.compile(r"\b(?:login|log in|sign in|account|password|register|registration|portal|member|dashboard|reset|verify|payment|billing|masuk|daftar)\b", re.I)
STRONG_TITLE = re.compile(r"\b(?:log\s?in|sign\s?in|register|registration|reset password|account|portal|dashboard|member login|password|sign up)\b", re.I)
PASSWORD_INPUT = re.compile(r"<input\b[^>]*type\s*=\s*['\"]?password\b", re.I)
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130 Safari/537.36"}
SECTOR_ORDER = ("government", "healthcare", "education", "nonprofit", "company", "funder", "other")


def sector(types: str) -> str:
    parts = {s.strip().lower() for s in re.split(r"[;|,]", types or "")}
    return next((s for s in SECTOR_ORDER if s in parts), "other")


def registry_records(seen: set[str]) -> list[dict]:
    if hashlib.md5(SOURCE.read_bytes()).hexdigest() != "5522990688eb1b94811a8145e131b41e":
        raise RuntimeError("ROR archive checksum mismatch")
    unique: dict[str, dict] = {}
    with zipfile.ZipFile(SOURCE) as archive:
        name = next(n for n in archive.namelist() if n.endswith(".csv"))
        with io.TextIOWrapper(archive.open(name), encoding="utf-8-sig", newline="") as stream:
            for row in csv.DictReader(stream):
                if row.get("status") != "active":
                    continue
                raw = (row.get("links.type.website") or "").split(";")[0].strip()
                if not raw.startswith(("https://", "http://")):
                    continue
                root = site_key(raw)
                if not root or root in seen or root in unique:
                    continue
                unique[root] = {
                    "site_key": root, "source_url": raw, "source_ror": row.get("id", ""),
                    "organization": row.get("names.types.ror_display", ""),
                    "sector": sector(row.get("types", "")),
                    "country": row.get("locations.geonames_details.country_code", "")[:2],
                    "continent": row.get("locations.geonames_details.continent_code", "")[:2],
                }
    groups: dict[str, list[dict]] = defaultdict(list)
    for item in unique.values():
        groups[item["sector"]].append(item)
    rng = random.Random(20261102)
    for group in groups.values():
        rng.shuffle(group)
    ordered = []
    while any(groups.values()):
        for key in SECTOR_ORDER:
            if groups[key]:
                ordered.append(groups[key].pop())
    return ordered


def inspect_website(item: dict) -> dict | None:
    home = page(item["source_url"].replace("http://", "https://", 1))
    if not home or site_key(home[0]) != item["site_key"]:
        return None
    homepage, _, soup = home
    choices: dict[str, tuple[int, str]] = {}
    for tag in soup.select("a[href]"):
        link = clean_url(urljoin(homepage, tag.get("href", "")))
        if not link or site_key(link) != item["site_key"]:
            continue
        path = urlsplit(link).path
        if path in ("", "/") or EXCLUDE_PATH.search(path):
            continue
        text = tag.get_text(" ", strip=True)[:100]
        path_auth = bool(AUTH.search(path))
        text_auth = bool(AUTH.search(text))
        if not path_auth and not text_auth:
            continue
        score = 2 if path_auth else 1
        if score > choices.get(link, (0, ""))[0]:
            choices[link] = (score, text)
    for link, (score, text) in sorted(choices.items(), key=lambda kv: (-kv[1][0], len(kv[0])))[:3]:
        try:
            response = requests.get(link, headers=HEADERS, timeout=(4, 10), allow_redirects=True)
            if response.status_code != 200 or "html" not in response.headers.get("content-type", "").lower():
                continue
            final = clean_url(response.url)
            if not final or site_key(final) != item["site_key"]:
                continue
            soup = BeautifulSoup(response.content[:650_000], "html.parser")
            title = soup.title.get_text(" ", strip=True)[:180] if soup.title else ""
            if not title or BAD.search(title):
                continue
            for tag in soup(["script", "style", "svg", "noscript"]):
                tag.decompose()
            body = soup.get_text(" ", strip=True)
            if len(body) < 160:
                continue
            password_field = bool(PASSWORD_INPUT.search(response.text[:200_000]))
            page_cue = bool(PAGE_CUE.search(title + " " + body[:2000]))
            if not (page_cue or password_field):
                continue
            return {**item, "url": link, "final_url": final, "title": title,
                    "link_text": text, "auth_in_url": bool(AUTH.search(urlsplit(link).path)),
                    "password_input_in_html": password_field, "page_cue": page_cue,
                    "http_status": 200, "checked_at_utc": datetime.now(timezone.utc).isoformat()}
        except (requests.RequestException, ValueError, UnicodeError):
            continue
    return None


def balanced_pick(found: list[dict], count: int) -> list[dict]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in found:
        groups[row["sector"]].append(row)
    for group in groups.values():
        group.sort(key=lambda x: (
            not (x["password_input_in_html"] or STRONG_TITLE.search(x["title"])),
            not x["auth_in_url"], not x["password_input_in_html"], x["site_key"]))
    selected = []
    country_count: Counter[str] = Counter()
    sector_count: Counter[str] = Counter()
    # Prefer actual login evidence across all sectors before admitting merely
    # account-like paths. Round-robin and caps prevent one sector dominating.
    for strong_only in (True, False):
        for country_cap, sector_cap in ((30, 80), (50, 120), (300, 300)):
            progress = True
            while len(selected) < count and progress:
                progress = False
                for key in SECTOR_ORDER:
                    if sector_count[key] >= sector_cap:
                        continue
                    for idx, row in enumerate(groups[key]):
                        strong = bool(row["password_input_in_html"] or STRONG_TITLE.search(row["title"]))
                        if strong_only and not strong or not strong_only and strong:
                            continue
                        country = row["country"] or "unknown"
                        if country_count[country] >= country_cap:
                            continue
                        groups[key].pop(idx)
                        selected.append(row)
                        country_count[country] += 1
                        sector_count[key] += 1
                        progress = True
                        break
                    if len(selected) >= count:
                        break
    return selected


def main() -> None:
    BASE.mkdir(exist_ok=True)
    helper = load_helpers()
    seen = excluded_sites(helper)
    # The previous 300 URL test and every earlier training/test domain are in
    # exclusions(). Current output must not be silently recycled on reruns.
    if OUTPUT.exists():
        seen.difference_update(site_key(u.strip()) for u in OUTPUT.read_text(encoding="utf-8").splitlines() if u.strip())
    candidates = registry_records(seen)
    completed = {}
    if CHECKPOINT.exists():
        for line in CHECKPOINT.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
                completed[row["site_key"]] = row
            except (ValueError, KeyError):
                continue
    found = [row["result"] for row in completed.values() if row.get("result") and row["site_key"] not in seen]
    print(f"ROR candidates={len(candidates)} completed={len(completed)} valid={len(found)}", flush=True)
    with ThreadPoolExecutor(max_workers=56) as pool, CHECKPOINT.open("a", encoding="utf-8") as log:
        for start in range(0, len(candidates), 140):
            if len(found) >= 520:
                break
            batch = [item for item in candidates[start:start + 140] if item["site_key"] not in completed]
            futures = {pool.submit(inspect_website, item): item for item in batch}
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
            print(f"checked={len(completed)}/{len(candidates)} valid={len(found)}", flush=True)
    unique = {row["site_key"]: row for row in found if row["site_key"] not in seen}
    selected = balanced_pick(list(unique.values()), 300)
    with AUDIT.open("w", encoding="utf-8-sig", newline="") as stream:
        fields = ["url", "final_url", "site_key", "title", "link_text", "organization", "source_ror", "source_url", "sector", "country", "continent", "auth_in_url", "password_input_in_html", "page_cue", "http_status", "checked_at_utc"]
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(selected)
    OUTPUT.write_text("\n".join(row["url"] for row in selected) + ("\n" if selected else ""), encoding="utf-8")
    summary = {"requested": 300, "prepared": len(selected), "unique_domains": len({row["site_key"] for row in selected}),
               "sector_counts": dict(Counter(row["sector"] for row in selected)),
               "continent_counts": dict(Counter(row["continent"] for row in selected)),
               "country_count": len({row["country"] for row in selected}),
               "auth_in_url": sum(row["auth_in_url"] for row in selected),
               "strong_login_form_or_title": sum(bool(row["password_input_in_html"] or STRONG_TITLE.search(row["title"])) for row in selected),
               "password_input_in_html": sum(row["password_input_in_html"] for row in selected),
               "prepared_at_utc": datetime.now(timezone.utc).isoformat(),
               "scope": "HTTP preflight only; full browser-extension analysis is not guaranteed"}
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
