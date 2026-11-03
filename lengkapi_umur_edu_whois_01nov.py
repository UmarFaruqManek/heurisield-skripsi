"""Cari tanggal registrasi .edu pada WHOIS registri, tanpa menebak umur."""

from __future__ import annotations

import json
import re
import socket
import time
from datetime import datetime, timezone
from pathlib import Path


AGE = Path(__file__).resolve().parent / "hasil_uji_xgboost_legitimate_300_01nov" / "umur_domain_rdap.jsonl"


def lookup(domain):
    try:
        with socket.create_connection(("whois.verisign-grs.com", 43), timeout=7) as sock:
            sock.settimeout(7)
            sock.sendall((domain + "\r\n").encode("ascii"))
            chunks = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                if sum(map(len, chunks)) > 100_000:
                    break
        body = b"".join(chunks).decode("utf-8", "replace")
        name = re.search(r"^\s*Domain Name:\s*(\S+)", body, re.I | re.M)
        date = re.search(r"^\s*Creation Date:\s*(\S+)", body, re.I | re.M)
        if not name or name.group(1).lower().rstrip(".") != domain or not date:
            return {"domain": domain, "status": "whois_no_verified_date"}
        created = datetime.fromisoformat(date.group(1).replace("Z", "+00:00"))
        if created > datetime.now(timezone.utc):
            return {"domain": domain, "status": "whois_future_date"}
        return {"domain": domain, "status": "found", "registered_at": created.isoformat(),
                "age_days": (datetime.now(timezone.utc).date() - created.date()).days,
                "provider": "verisign_whois_edu"}
    except (OSError, ValueError) as exc:
        return {"domain": domain, "status": type(exc).__name__}


def main():
    cache = {}
    for line in AGE.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        cache[row["domain"]] = row
    missing = sorted(domain for domain, row in cache.items() if domain.endswith(".edu") and row.get("status") != "found")
    print(f"WHOIS .edu: {len(missing)} domain", flush=True)
    with AGE.open("a", encoding="utf-8") as handle:
        for i, domain in enumerate(missing, 1):
            row = lookup(domain)
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            handle.flush()
            cache[domain] = row
            if i % 20 == 0 or i == len(missing):
                print(f"WHOIS {i}/{len(missing)}; ditemukan={sum(v.get('status') == 'found' for v in cache.values())}", flush=True)
            time.sleep(0.6)


if __name__ == "__main__":
    main()
