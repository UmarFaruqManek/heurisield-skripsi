"""Recreate the local evaluation index from the included per-URL reports."""

from pathlib import Path
from analysis_history_db import import_report


root = Path(__file__).resolve().parents[2]
database = root / "hasil" / "database_evaluasi" / "riwayat_analisis.sqlite"
reports = sorted((root / "hasil").rglob("browser_live_analysis.json"))
total = 0
for report in reports:
    run_id, count = import_report(database, report.parent)
    total += count
    print(f"{report.parent.relative_to(root)}: {count} URL ({run_id})")
print(f"Selesai: {len(reports)} pengujian, {total} rekaman; {database}")
