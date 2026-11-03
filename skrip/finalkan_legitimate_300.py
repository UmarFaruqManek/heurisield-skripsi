"""Bekukan 300 kandidat legitimate untuk uji XGBoost URL saja."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd
import tldextract


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data/input_uji/kandidat_legitimate_baru_01nov"
AUDIT = OUT / "audit_http.csv"
SITE = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
DOWNLOADS = Path(r"C:\Users\USER\Downloads")
TRUSTED_SUFFIXES = (
    ".ac.id", ".go.id", ".sch.id", ".edu", ".gov", ".ac.uk", ".edu.au",
    ".gov.au", ".gov.uk", ".edu.my", ".edu.sg", ".edu.ph", ".ac.nz",
    ".edu.hk", ".edu.tw", ".ac.jp", ".ac.kr", ".ac.za", ".ac.th",
    ".edu.vn", ".edu.bd", ".edu.ng", ".edu.pk", ".edu.tr", ".edu.br",
    ".edu.mx", ".edu.ar", ".edu.co", ".edu.pe", ".edu.eg", ".edu.sa",
    ".edu.ae", ".edu.qa", ".edu.in", ".ac.in", ".ac.ke", ".ac.ug",
    ".gov.in", ".gov.it", ".gov.my", ".gov.ph", ".gov.sa", ".gov.ae",
    ".gov.qa", ".gov.pt", ".gov.za", ".gov.br",
)
CURATED_SITES = {
    "zoom.com", "hashicorp.com", "revolut.com", "repec.org", "ontario.ca",
    "utm.edu", "xmission.com", "wikinews.org", "posit.co", "sulekha.com",
    "divx.com", "ticketleap.com", "yabla.com", "singaporeexpats.com", "drew.edu",
    "aapg.org", "yugabyte.com", "westernu.edu", "foxrothschild.com",
    "nativeweb.org", "k12.sd.us", "celeryq.dev", "accesscomm.ca",
}
WEB_ADDITIONAL_SITES = {"donorbox.org"}
SESSION_PATTERN = re.compile(r"sessionDataKey|p_auth=|wct=|execution=|sid=", re.I)
LOGIN_PATTERN = re.compile(r"login|log-in|signin|sign-in|account|verify|auth|secure|portal|password|registr", re.I)


def main():
    table = pd.read_csv(AUDIT, keep_default_na=False)
    table = table[table.verified == True].copy()
    table = table[~table.url.str.contains(SESSION_PATTERN)].copy()
    table = table[table.url.map(lambda u: bool([part for part in urlsplit(u).path.split("/") if part]))].copy()
    table = table[
        ((table.source == "web_search") & (table.site.str.endswith(TRUSTED_SUFFIXES) | table.site.isin(WEB_ADDITIONAL_SITES)))
        | ((table.source == "curated_2000") & table.site.isin(CURATED_SITES))
    ].copy()
    table = table.drop_duplicates(subset=["site"])
    if len(table) < 300:
        raise RuntimeError(f"Hanya {len(table)} URL lolos, tidak membuat URL tambahan.")
    table["login_like"] = table.url.str.contains(LOGIN_PATTERN)
    table["source_priority"] = table.source.map({"web_search": 0, "curated_2000": 1})
    table = table.sort_values(["login_like", "source_priority", "tranco_rank"],
                              ascending=[False, True, True], na_position="last").head(300).copy()
    table = table.drop(columns=["source_priority"])
    table["subdomain_count"] = table.url.map(
        lambda u: len([part for part in SITE(urlsplit(u).hostname or "").subdomain.split(".") if part and part != "www"])
    )
    table["path_depth"] = table.url.map(
        lambda u: len([part for part in urlsplit(u).path.split("/") if part])
    )
    assert len(table) == len(set(table.url)) == len(set(table.site)) == 300
    assert table.subdomain_count.min() >= 1 and table.path_depth.min() >= 1
    assert set(table.http_status.astype(str)) == {"200"}
    urls = table.url.tolist()
    (OUT / "legitimate_fresh_300_subdomain_path_01nov.txt").write_text("\n".join(urls) + "\n", encoding="utf-8")
    (DOWNLOADS / "legitimate_fresh_300_subdomain_path_01nov.txt").write_text("\n".join(urls) + "\n", encoding="utf-8")
    table.to_csv(OUT / "audit_final_300.csv", index=False, encoding="utf-8-sig")
    report = {
        "total": 300,
        "unique_urls": len(set(table.url)),
        "unique_sites": len(set(table.site)),
        "verified_http_200_same_site_html": 300,
        "with_login_like_text": int(table.login_like.sum()),
        "with_two_or_more_subdomains": int((table.subdomain_count >= 2).sum()),
        "with_path_depth_two_or_more": int((table.path_depth >= 2).sum()),
        "sources": dict(Counter(table.source)),
        "limitations": [
            "HTTP 200 and same site were checked when preparing the list; this does not prove page content or identity.",
            "Selected domains were excluded from the model corpus and named earlier test files available locally.",
            "This is a candidate list for a URL-only test; no model scoring or browser test has been run.",
        ],
    }
    (OUT / "ringkasan_final_300.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
