"""Indeks seluruh PDF lokal dan temukan halaman yang membahas fitur URL.

Skrip ini hanya membaca PDF dan menyimpan indeks ringkas; tidak menyalin isi lengkap.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from pypdf import PdfReader


SOURCE = Path(r"D:\Deployment Extension\Refrensi SkripsiKU")
OUT = Path(__file__).resolve().parents[1] / "hasil/ringkasan/audit_referensi_semua.json"
TERMS = {
    "url_length": r"(?:URL[ -]?length|panjang\s+URL|length of (?:the )?URL)",
    "domain_age": r"(?:domain age|age of (?:the )?domain|umur domain|usia domain)",
    "ip_host": r"(?:IP[- ]?based|IP address|alamat IP|having IP)",
    "https": r"(?:HTTPS|SSL certificate)",
    "subdomain": r"(?:subdomain|sub[ -]?domain)",
    "hyphen": r"(?:hyphen|tanda hubung|prefix suffix)",
    "dot": r"(?:number of dots|jumlah titik|dot count)",
    "path": r"(?:path[- ]?length|path depth|depth of (?:the )?URL|URL path|panjang path)",
    "query": r"(?:query[- ]?length|query parameter|query string)",
    "digit": r"(?:digit count|number of digits|digit ratio|jumlah angka|rasio angka)",
    "entropy": r"(?:entropy|entropi)",
    "special": r"(?:special character|karakter khusus|@ symbol|simbol @)",
    "keyword": r"(?:keyword|kata kunci|sensitive word|phishing word)",
    "redirect": r"(?:redirect|pengalihan)",
    "shortener": r"(?:shorten(?:ing|er|ed)? service|URL pendek|pemendek URL)",
    "brand": r"(?:brand|merek)",
    "dom": r"(?:Document Object Model|HTML content|halaman web|credential form)",
}
REGEX = {k: re.compile(v, re.I) for k, v in TERMS.items()}


def main() -> None:
    logging.getLogger("pypdf").setLevel(logging.ERROR)
    rows = []
    for pdf in sorted(SOURCE.glob("*.pdf"), key=lambda p: p.name.lower()):
        row = {"file": pdf.name, "pages": 0, "extractable_pages": 0,
               "matched_pages": {}, "first_page_excerpt": "", "error": None}
        try:
            reader = PdfReader(str(pdf))
            row["pages"] = len(reader.pages)
            for i, page in enumerate(reader.pages, 1):
                raw = page.extract_text() or ""
                s = " ".join(raw.split())
                if len(s) >= 80:
                    row["extractable_pages"] += 1
                if i == 1:
                    row["first_page_excerpt"] = s[:500]
                for term, pattern in REGEX.items():
                    match = pattern.search(s)
                    if match:
                        row["matched_pages"].setdefault(term, []).append(i)
        except Exception as error:
            row["error"] = f"{type(error).__name__}: {error}"
        rows.append(row)
        print(f"{len(rows):02d}/43 {row['pages']:3d} pages, {row['extractable_pages']:3d} readable: {pdf.name}", flush=True)
    OUT.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Saved: {OUT}")


if __name__ == "__main__":
    main()
