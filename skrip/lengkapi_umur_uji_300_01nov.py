"""Lengkapi umur yang gagal di RDAP melalui API cadangan, dengan checkpoint."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import requests


OUT = Path(__file__).resolve().parents[1] / "hasil/hasil_uji_xgboost_legitimate_300_01nov"
AGE = OUT / "umur_domain_rdap.jsonl"
PROVIDERS = (
    ("whodat", "https://who-dat.as93.net/{domain}"),
    ("beryl", "https://api-check-beryl-beta.vercel.app/api/whois?domain={domain}"),
    ("dun", "https://whois-api-dun.vercel.app/api/whois?domain={domain}"),
)


def date_from(payload, domain):
    if not isinstance(payload, dict):
        return None
    if payload.get("isRegistered") is False:
        return None
    values = [payload]
    for key in ("data", "result", "whois", "rdap"):
        if isinstance(payload.get(key), dict):
            values.append(payload[key])
    for item in values:
        reported = str(item.get("domain") or item.get("domainName") or item.get("query") or "").lower().rstrip(".")
        if reported and reported != domain:
            continue
        candidates = [item.get(key) for key in (
            "created_date", "registration_date", "domain_creation_date", "creationDate",
            "registrationDate", "createdDate", "registeredOn", "created")]
        if isinstance(item.get("dates"), dict):
            candidates.append(item["dates"].get("created"))
        for value in candidates:
            if not value:
                continue
            try:
                created = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                created = created.astimezone(timezone.utc)
                if created <= datetime.now(timezone.utc):
                    return created
            except ValueError:
                pass
    return None


def main():
    cache = {}
    for line in AGE.read_text(encoding="utf-8").splitlines():
        item = json.loads(line)
        cache[item["domain"]] = item
    missing = [domain for domain, item in cache.items() if item.get("status") != "found"]
    cooldown = set()
    print(f"API cadangan untuk {len(missing)} domain; urutan whodat, beryl, dun.", flush=True)
    with AGE.open("a", encoding="utf-8") as file:
        for i, domain in enumerate(missing, 1):
            result = {"domain": domain, "status": "fallback_unavailable", "attempts": {}}
            for name, template in PROVIDERS:
                if name in cooldown:
                    result["attempts"][name] = "cooldown"
                    continue
                try:
                    response = requests.get(template.format(domain=domain), timeout=12,
                                            headers={"User-Agent": "HeuriShield research evaluation/1.0"})
                    result["attempts"][name] = response.status_code
                    if response.status_code == 429:
                        cooldown.add(name)
                        continue
                    if response.status_code != 200:
                        continue
                    created = date_from(response.json(), domain)
                    if created:
                        result.update({"status": "found", "registered_at": created.isoformat(),
                                       "age_days": (datetime.now(timezone.utc).date() - created.date()).days,
                                       "provider": name})
                        break
                except (requests.RequestException, ValueError) as exc:
                    result["attempts"][name] = type(exc).__name__
                time.sleep(0.30)
            cache[domain] = result
            file.write(json.dumps(result, ensure_ascii=False) + "\n")
            file.flush()
            if i % 25 == 0 or i == len(missing):
                print(f"Cadangan {i}/{len(missing)}; umur tersedia={sum(v.get('status') == 'found' for v in cache.values())}", flush=True)
    print("Selesai; jalankan ulang skrip/uji_xgboost_legitimate_300_01nov.py untuk skor akhir.", flush=True)


if __name__ == "__main__":
    main()
