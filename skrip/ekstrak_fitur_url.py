r"""Ekstrak 17 fitur URL dan bawa umur domain teramati dari dataset.

Tidak mengakses website atau API. Jalankan dari folder ini:
    python .\ekstrak_fitur_url.py --dry-run
    python .\ekstrak_fitur_url.py

Input default: HeuriShield_URL_Label_Umur_Domain_Seimbang.xlsx
Output default: data/dataset/DATA_URL_18_FITUR.csv dan hasil/ringkasan/RINGKASAN_EKSTRAKSI_URL.json
"""

from __future__ import annotations

import argparse
from collections import Counter
import csv
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

import tldextract


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "HeuriShield_URL_Label_Umur_Domain_Seimbang.xlsx"
DEFAULT_OUTPUT = ROOT / "data/dataset/DATA_URL_18_FITUR.csv"
SUMMARY = ROOT / "hasil/ringkasan/RINGKASAN_EKSTRAKSI_URL.json"
ERRORS = ROOT / "URL_GAGAL_DIEKSTRAK.csv"

# Gunakan PSL bawaan paket tanpa unduhan. Private suffix seperti pages.dev
# dianggap batas situs; ac.id tetap dikenali sebagai public suffix bertingkat.
DOMAIN_PARSER = tldextract.TLDExtract(
    suffix_list_urls=(), include_psl_private_domains=True
)

# Kamus ini harus identik jika ekstraktor kelak ditulis dalam JavaScript.
SENSITIVE_TOKENS = frozenset({
    "account", "admin", "auth", "confirm", "login", "logon", "otp",
    "password", "reset", "secure", "signin", "update", "verification",
    "verify",
})
ASCII_TOKEN = re.compile(r"[A-Za-z0-9]+")
NON_ASCII_ALNUM = re.compile(r"[^A-Za-z0-9]")

URL_FEATURES = (
    "url_length", "hostname_length", "path_length", "query_length",
    "subdomain_count", "path_depth", "dot_count", "hyphen_count",
    "digit_ratio", "special_char_count", "has_at_symbol", "has_ip_host",
    "has_https_scheme", "hostname_entropy", "sensitive_token_count",
    "url_entropy", "path_hyphen_count",
)
OUTPUT_COLUMNS = ("url", "label", "domain_age_days", *URL_FEATURES)
LABELS = {"legitimate", "phishing"}


def shannon_entropy(value: str) -> float:
    """Entropi Shannon karakter, dibulatkan untuk hasil CSV yang stabil."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return round(-sum((count / length) * math.log2(count / length)
                      for count in counts.values()), 6)


def extract_url_features(url: str) -> dict[str, int | float]:
    """Semua fitur di sini hanya menggunakan teks URL awal, bukan halaman akhir."""
    raw = str(url).strip()
    if not raw:
        raise ValueError("URL kosong")
    parsed = urlsplit(raw)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL harus memakai http(s) dan memiliki hostname")

    # IDN ditulis sebagai ASCII/Punycode agar nama host punya satu representasi.
    try:
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as exc:
        raise ValueError("hostname IDN tidak valid") from exc

    try:
        ipaddress.ip_address(host)
        is_ip = True
        subdomain_count = 0
    except ValueError:
        is_ip = False
        result = DOMAIN_PARSER(host)
        subdomain_count = len([part for part in result.subdomain.split(".") if part])

    # Browser memperlakukan URL tanpa path eksplisit sebagai path root '/'.
    path = parsed.path or "/"
    query = parsed.query
    path_query = path + query
    tokens = ASCII_TOKEN.findall((unquote(path) + "?" + unquote(query)).lower())
    digit_count = sum(char in "0123456789" for char in host)

    return {
        "url_length": len(raw),
        "hostname_length": len(host),
        "path_length": len(path),
        "query_length": len(query),
        "subdomain_count": subdomain_count,
        "path_depth": len([part for part in path.split("/") if part]),
        "dot_count": host.count("."),
        "hyphen_count": host.count("-"),
        "digit_ratio": round(digit_count / len(host), 6),
        "special_char_count": len(NON_ASCII_ALNUM.findall(path_query)),
        "has_at_symbol": int("@" in raw),
        "has_ip_host": int(is_ip),
        "has_https_scheme": int(parsed.scheme.lower() == "https"),
        "hostname_entropy": shannon_entropy(host),
        "sensitive_token_count": sum(token in SENSITIVE_TOKENS for token in tokens),
        "url_entropy": shannon_entropy(raw),
        "path_hyphen_count": path.count("-"),
    }


def source_rows(path: Path):
    """Baca Excel atau CSV tanpa memuat seluruh dataset ke memori."""
    if path.suffix.lower() == ".xlsx":
        from openpyxl import load_workbook

        workbook = load_workbook(path, read_only=True, data_only=True)
        rows = workbook.active.iter_rows(values_only=True)
        headers = next(rows, None)
        if headers is None:
            raise ValueError("File Excel kosong")
        expected = {"url", "label"}
        if not expected.issubset(headers):
            raise ValueError(f"Kolom wajib tidak tersedia: {expected - set(headers)}")
        age_column = "domain_age_days" if "domain_age_days" in headers else "umur_domain_hari"
        if age_column not in headers:
            raise ValueError("Kolom umur domain tidak tersedia")
        index = {name: headers.index(name) for name in ("url", "label", age_column)}
        try:
            for line, row in enumerate(rows, start=2):
                yield line, {name: row[pos] for name, pos in index.items()}, age_column
        finally:
            workbook.close()
    elif path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            headers = reader.fieldnames or []
            if "url" not in headers or "label" not in headers:
                raise ValueError("Kolom url dan label tidak tersedia")
            age_column = "domain_age_days" if "domain_age_days" in headers else "umur_domain_hari"
            if age_column not in headers:
                raise ValueError("Kolom umur domain tidak tersedia")
            for line, row in enumerate(reader, start=2):
                yield line, row, age_column
    else:
        raise ValueError("Input harus .xlsx atau .csv")


def age_value(value) -> int | float | str:
    if value is None or str(value).strip() == "":
        return ""
    age = float(value)
    if not math.isfinite(age) or age < 0:
        raise ValueError("umur domain bukan angka nonnegatif")
    return int(age) if age.is_integer() else age


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    source = args.input.resolve()
    if not source.is_file():
        parser.error(f"Input tidak ditemukan: {source}")
    output = args.output.resolve()
    if output == source:
        parser.error("Output tidak boleh sama dengan input")

    counts = Counter()
    failed = []
    seen = set()
    temporary = output.with_name(output.name + ".tmp")
    if not args.dry_run:
        output.parent.mkdir(parents=True, exist_ok=True)
        stream = temporary.open("w", encoding="utf-8", newline="")
        writer = csv.DictWriter(stream, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
    else:
        stream = None
        writer = None

    try:
        for line, row, age_column in source_rows(source):
            url = str(row["url"] or "").strip()
            label = str(row["label"] or "").strip().lower()
            counts["source_rows"] += 1
            try:
                if label not in LABELS:
                    raise ValueError(f"label tidak dikenal: {label}")
                if url in seen:
                    raise ValueError("URL duplikat")
                seen.add(url)
                features = extract_url_features(url)
                age = age_value(row[age_column])
                record = {"url": url, "label": label,
                          "domain_age_days": age, **features}
                if writer:
                    writer.writerow(record)
                counts[label] += 1
                if age == "":
                    counts["age_missing"] += 1
            except (ValueError, TypeError) as exc:
                failed.append({"line": line, "url": url,
                               "label": label, "reason": str(exc)})
    finally:
        if stream:
            stream.close()

    summary = {
        "source": str(source),
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "output": str(output),
        "dry_run": args.dry_run,
        "feature_count": len(URL_FEATURES) + 1,
        "url_feature_count": len(URL_FEATURES),
        "feature_names": [*URL_FEATURES, "domain_age_days"],
        "rows": dict(counts),
        "failed_rows": len(failed),
        "parsing": "URL awal, whitespace tepi dihapus, hostname IDN ASCII; PSL bundel + private suffix",
        "age": "disalin dari sumber; tidak dicek ulang melalui API",
    }
    if not args.dry_run:
        temporary.replace(output)
        SUMMARY.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        if failed:
            with ERRORS.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=("line", "url", "label", "reason"))
                writer.writeheader()
                writer.writerows(failed)
        elif ERRORS.exists():
            ERRORS.unlink()
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    if failed:
        print("Contoh gagal:", json.dumps(failed[:5], ensure_ascii=False))


if __name__ == "__main__":
    main()
