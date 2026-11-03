"""Freeze small, domain-disjoint live inputs for the 2026-11-02 audit."""
import csv
import glob
import json
from datetime import datetime, timezone
from pathlib import Path

import requests
import tldextract

ROOT = Path(__file__).resolve().parent
PROJECT = ROOT.parents[1]
TRAIN = PROJECT / "data/dataset/DATA_URL_18_FITUR.csv"
OFFICIAL = [
    "https://sso.pom.go.id/",
    "https://mahasiswa.umsu.ac.id/Account/Login",
    "https://simak.unkris.ac.id/",
    "https://simka.uit.ac.id/mahasiswa/web/index.php?r=site%2Flogin",
    "https://fp.um-palembang.ac.id/simak/id/login/",
    "https://simak.uss.ac.id/",
    "https://simak.ua.ac.id/?portal_notice=login",
    "https://simakad.um-ad.ac.id/",
    "https://simak.unpak.ac.id/",
    "https://simak.unikarta.ac.id/",
    "https://sso.jogjaprov.go.id/",
    "https://satamasn.babelprov.go.id/web/auth/login",
    "https://simak.ipb.ac.id/Account/Login?ReturnUrl=%2FRef%2FPanduan%2FIndex",
    "https://akademik.unikom.ac.id/",
    "https://siakad.ugk.ac.id/baak-ugk/index.php",
    "https://siak.ummu.ac.id/?act=login",
    "https://my.utpb.edu/",
    "https://connect.calcoast.edu/sign-in",
]


def domain(url):
    return tldextract.extract(url).top_domain_under_public_suffix


train = {domain(row["url"]) for row in csv.DictReader(TRAIN.open(encoding="utf-8-sig", newline=""))}
prior = set()
for path in glob.glob(str(PROJECT / "**" / "browser_live_analysis.json"), recursive=True):
    if str(ROOT) in path:
        continue
    for record in json.loads(Path(path).read_text(encoding="utf-8")).get("records", []):
        if record.get("input_url"):
            prior.add(domain(record["input_url"]))

response = requests.get("https://openphish.com/feed.txt", timeout=20)
response.raise_for_status()
feed = [line.strip() for line in response.text.splitlines() if line.startswith(("http://", "https://"))]


def choose(urls, limit):
    selected, seen = [], set()
    for url in urls:
        root = domain(url)
        if not root or root in train or root in prior or root in seen:
            continue
        seen.add(root)
        selected.append(url)
        if len(selected) == limit:
            break
    return selected


legitimate = choose(OFFICIAL, 15)
phishing = choose(feed, 15)
if len(legitimate) != 15 or len(phishing) != 15:
    raise RuntimeError(f"Insufficient unused domains: legitimate={len(legitimate)}, phishing={len(phishing)}")
for label, urls in (("legitimate", legitimate), ("phishing", phishing)):
    (ROOT / f"{label}_15.txt").write_text("\n".join(urls) + "\n", encoding="utf-8")
manifest = {
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "extension": str(PROJECT / "extension/HeuriShield-URL18-XGBoost"),
    "train_source": str(TRAIN),
    "prior_live_analysis_files_checked": len(glob.glob(str(PROJECT / "**" / "browser_live_analysis.json"), recursive=True)),
    "source_legitimate": "Official organization pages found by web search, 2026-11-02; each label requires live verification",
    "source_phishing": "https://openphish.com/feed.txt",
    "feed_rows": len(feed),
    "legitimate_count": len(legitimate),
    "phishing_count": len(phishing),
    "domain_disjoint_from_train_and_prior": True,
}
(ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
print(json.dumps(manifest, indent=2))
