"""Inventaris CSV yang mungkin memuat URL dan label aktual."""

import csv
import json
from pathlib import Path

ROOTS = [Path(r"D:\mesin crawl"), Path(r"D:\Deployment Extension"),
         Path(r"D:\experimen"), Path(r"C:\Users\USER\Downloads")]
OUT = Path(__file__).resolve().parents[1] / "hasil/ringkasan/inventaris_dataset.json"
URL_COLUMNS = {"url", "input_url", "original_url", "source_url", "normalized_url", "url_original"}
LABEL_COLUMNS = {"label", "expected_label", "actual_label", "class", "target", "status"}
AGE_COLUMNS = {"domain_age_days", "original_domain_age_days", "source_domain_age_days", "age_of_domain"}


def main():
    records = []
    for root in ROOTS:
        for path in root.rglob("*.csv"):
            try:
                with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as file:
                    headers = next(csv.reader(file), [])
                names = {x.strip().lower() for x in headers}
                url = sorted(names & URL_COLUMNS)
                label = sorted(names & LABEL_COLUMNS)
                age = sorted(names & AGE_COLUMNS)
                if not url or not label:
                    continue
                records.append({"path": str(path), "bytes": path.stat().st_size,
                                "url_columns": url, "label_columns": label,
                                "age_columns": age})
            except (OSError, csv.Error):
                continue
    records.sort(key=lambda x: x["bytes"], reverse=True)
    OUT.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
    print("Candidates:", len(records))
    for record in records[:100]:
        print(record["bytes"], record["path"], record["url_columns"], record["label_columns"], record["age_columns"])


if __name__ == "__main__":
    main()
