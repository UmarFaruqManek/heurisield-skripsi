#!/usr/bin/env python3
"""Evaluate HeuriShield by loading the unpacked extension in a real browser.

This is intentionally different from the fetch/runtime evaluators: every URL is
opened in Chromium/Chrome with the extension enabled, so content scripts,
webNavigation auto-analysis, block-page redirects, RDAP/brand fetches, and
chrome.storage writes follow the extension path.
"""

from __future__ import annotations

import argparse
import hashlib
import asyncio
from collections import Counter
import csv
import json
import random
import re
import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, parse_qs, parse_qsl, urlencode

from playwright.async_api import async_playwright
from consolidate_live_analysis import consolidate_live_analysis
from analysis_history_db import import_report


VERDICT_BY_LABEL = {
    "legitimate": "SAFE",
    "phishing": "DANGEROUS",
}

OUTPUT_FIELDS = [
    "analysis_status", "elapsed_seconds", "raw_probability_phishing", "raw_verdict",
    "index", "input_url", "input_domain", "expected_label", "expected_verdict",
    "actual_verdict", "correct", "browser_final_url", "page_title", "analysis_url",
    "analysis_final_url", "registrable_domain", "score", "probability_phishing",
    "threshold", "post_model_guard", "fired_rule_count", "brand_name",
    "brand_domain", "brand_identity_status", "brand_identity_active_domain",
    "brand_identity_candidate_domain", "brand_identity_method",
    "brand_identity_hostname_claim", "brand_identity_title_claim",
    "brand_identity_credential_form", "brand_identity_fallback_status",
    "brand_identity_page_claim_domain", "brand_identity_page_claim_name",
    "source_domain_age_days", "page_domain_age_days",
    "feature_coverage_percent", "reasons", "displayed_reasons", "error",
    "observed_warning_verdict",
    "site_http_status", "response_category", "redirect_category",
    "warning_context_state", "warning_target_url", "no_analysis_reason",
]


def read_urls(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8-sig", errors="ignore")
    urls: list[str] = []

    if path.suffix.lower() == ".csv":
        rows = list(csv.DictReader(text.splitlines()))
        if rows:
            field = next((name for name in rows[0].keys() if name and name.lower() in {"url", "urls", "link"}), None)
            if field:
                urls = [str(row.get(field, "")).strip() for row in rows]
            else:
                first = next(iter(rows[0].keys()))
                urls = [str(row.get(first, "")).strip() for row in rows]
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.search(r"https?://[^\s,;\"'<>]+", line)
            if match:
                urls.append(match.group(0).strip())

    clean: list[str] = []
    seen = set()
    for url in urls:
        url = url.strip().strip('"').strip("'")
        if not url:
            continue
        if not re.match(r"^https?://", url, re.I):
            url = f"https://{url}"
        if url not in seen:
            clean.append(url)
            seen.add(url)
    return clean


def safe_domain(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def csv_value(value):
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return value


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: csv_value(row.get(field)) for field in fields})


def is_warning_url(url: str, extension_id: str | None = None) -> bool:
    parsed = urlparse(url or "")
    if parsed.scheme != "chrome-extension":
        return False
    if extension_id and parsed.netloc != extension_id:
        return False
    return parsed.path.endswith("/src/warning/warning.html")


def warning_context_id(url: str) -> str:
    try:
        parsed = urlparse(url or "")
        return (parse_qs(parsed.query).get("id") or [""])[0]
    except Exception:
        return ""


async def get_service_worker(context, extension_id: str | None = None):
    for worker in context.service_workers:
        if worker.url.startswith("chrome-extension://"):
            if not extension_id or worker.url.split("/")[2] == extension_id:
                return worker
    worker = await context.wait_for_event("serviceworker", timeout=15000)
    return worker


async def find_extension_id_with_cdp(context, page) -> str | None:
    session = await context.new_cdp_session(page)
    targets = await session.send("Target.getTargets")
    for info in targets.get("targetInfos", []):
        url = info.get("url") or ""
        if url.startswith("chrome-extension://"):
            parts = url.split("/")
            if len(parts) > 2:
                return parts[2]
    return None


async def ensure_extension_worker(context, page):
    try:
        return await get_service_worker(context)
    except Exception:
        extension_id = await find_extension_id_with_cdp(context, page)
        if extension_id:
            try:
                await page.goto(f"chrome-extension://{extension_id}/src/options/options.html", wait_until="domcontentloaded", timeout=10000)
            except Exception:
                pass
            return await get_service_worker(context, extension_id)
        raise


async def extension_storage(worker, keys):
    return await worker.evaluate(
        """(keys) => new Promise((resolve) => chrome.storage.local.get(keys, resolve))""",
        keys,
    )


async def extension_set_storage(worker, patch):
    await worker.evaluate(
        """(patch) => new Promise((resolve) => chrome.storage.local.set(patch, resolve))""",
        patch,
    )


async def latest_analysis(worker, tab_id=None):
    result = await extension_storage(worker, ["analysisByTab"])
    by_tab = result.get("analysisByTab") or {}
    analyses = [item for item in by_tab.values() if isinstance(item, dict)
                and (tab_id is None or item.get('tab_id') == tab_id)]
    if not analyses:
        return None
    analyses.sort(key=lambda item: item.get("analyzed_at") or "", reverse=True)
    return analyses[0]


async def warning_context(worker, context_id: str):
    if not context_id:
        return None
    result = await extension_storage(worker, ["warningContexts"])
    contexts = result.get("warningContexts") or {}
    context = contexts.get(context_id)
    return context if isinstance(context, dict) else None


def comparable_url(url: str) -> str:
    parsed = urlparse(url or "")._replace(fragment="")
    # Browser menormalisasi https://domain menjadi https://domain/. Tanpa ini,
    # analisis pada block page salah ditolak karena input dan URL HTTP yang
    # diamati dianggap berbeda, khususnya untuk feed URL tanpa path.
    if parsed.scheme.lower() in {"http", "https"} and parsed.netloc and not parsed.path:
        parsed = parsed._replace(path="/")
    return parsed.geturl()


def comparable_analysis_url(url: str) -> str:
    """Match persisted analysis URLs after the extension removes auth query keys."""
    parsed = urlparse(comparable_url(url))
    if parsed.scheme.lower() not in {"http", "https"}:
        return parsed.geturl()
    kept = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            if not re.search(r"code|state|token|secret|nonce|key|password|pass|otp|auth|session|ticket|credential|client_id|redirect_uri", key, re.I)]
    return parsed._replace(query=urlencode(kept)).geturl()


def last_site_http_status(document_status: dict) -> int | None:
    # The warning page itself returns 200; only the website response counts.
    site_statuses = [status for response_url, status in document_status.items()
                     if urlparse(response_url).scheme in {"http", "https"}]
    return site_statuses[-1] if site_statuses else None


def observed_warning_verdict(browser_final_url: str, extension_id: str,
                             document_status: dict) -> bool:
    # Restore the old observable-block outcome only when the source page loaded.
    # This does not claim that its complete feature vector was recovered.
    return (is_warning_url(browser_final_url, extension_id)
            and bool(warning_context_id(browser_final_url))
            and last_site_http_status(document_status) == 200)


def response_category(status: int | None, title: str = "") -> str:
    if status == 403:
        return "http_403_denied"
    if status == 404 or re.search(r"page not found|site not found", title, re.I):
        return "not_found"
    if status == 410:
        return "http_410_gone"
    if status is not None and status >= 400:
        return f"http_{status}_error"
    if re.search(r"access denied|client challenge|just a moment|verify.*human", title, re.I):
        return "access_challenge"
    if re.search(r"account suspended|site suspended", title, re.I):
        return "site_suspended"
    return "page_loaded" if status is not None and status < 400 else "http_status_unobserved"


def redirect_category(input_url: str, final_url: str, warning_url: bool = False) -> str:
    if warning_url:
        return "extension_warning"
    original_host, final_host = safe_domain(input_url), safe_domain(final_url)
    if not final_host:
        return "unknown"
    if original_host != final_host:
        return "cross_host"
    return "same_host" if comparable_url(input_url) != comparable_url(final_url) else "none"


def timestamp_ms(value: str) -> int:
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)
    except (AttributeError, ValueError, TypeError):
        return 0


def valid_current_analysis(analysis, started_at_ms, tab_id, input_url, observed_urls, context_time=None):
    if not isinstance(analysis, dict):
        return False
    if tab_id is not None and analysis.get("tab_id") != tab_id:
        return False
    if not (analysis.get("model_result") or {}).get("ready"):
        return False
    if analysis.get("verdict") not in {"SAFE", "DANGEROUS"}:
        return False
    if max(timestamp_ms(analysis.get("analyzed_at")), timestamp_ms(context_time)) < started_at_ms:
        return False
    observed = {comparable_url(u) for u in (observed_urls or ())}
    input_key = comparable_url(input_url)
    candidates = {comparable_url(analysis.get(k)) for k in ("url", "original_url", "final_url")}
    candidates.discard("")
    if input_url and input_key not in candidates:
        # The model can analyze the full URL while its persisted record removes
        # authentication query values. Require the original navigation to have
        # been observed before accepting that redacted record.
        redacted_input = comparable_analysis_url(input_url)
        redacted_candidates = {comparable_analysis_url(candidate) for candidate in candidates}
        if input_key in observed and redacted_input in redacted_candidates:
            return True
        # A redirect is accepted only if the browser observed both the input and the analyzed URL.
        redacted_observed = {comparable_analysis_url(item) for item in observed}
        if input_key not in observed or not (redacted_candidates & redacted_observed):
            return False
    return True


async def current_warning_analysis(worker, page_url, extension_id, started_at_ms, tab_id, input_url, observed_urls):
    if not is_warning_url(page_url, extension_id):
        return None
    context = await warning_context(worker, warning_context_id(page_url))
    if not context:
        return None
    analysis = context.get("analysis")
    if (valid_current_analysis(analysis, started_at_ms, tab_id, input_url, observed_urls,
                               context.get("created_at"))
            and analysis.get("verdict") == "DANGEROUS"):
        return analysis
    return None


async def wait_for_analysis(worker, started_at_ms: int, timeout_ms: int, tab_id=None,
                            input_url=None, page=None, extension_id=None, observed_urls=None):
    deadline = time.monotonic() + timeout_ms / 1000
    last = None
    while time.monotonic() < deadline:
        last = await latest_analysis(worker, tab_id)
        if valid_current_analysis(last, started_at_ms, tab_id, input_url, observed_urls):
            return last
        if page is not None and extension_id:
            blocked = await current_warning_analysis(worker, page.url, extension_id,
                started_at_ms, tab_id, input_url, observed_urls)
            if blocked:
                return blocked
        await asyncio.sleep(0.5)
    return None


def compact_reasons(analysis: dict | None) -> str:
    if not analysis:
        return ""
    rules = analysis.get("matched_rules") or []
    reasons = []
    for rule in rules[:8]:
        reason = rule.get("reason") or rule.get("id")
        if reason:
            reasons.append(str(reason))
    return " | ".join(reasons)


def row_from_analysis(index: int, input_url: str, expected_label: str, analysis: dict | None, error: str = "") -> dict:
    expected_verdict = VERDICT_BY_LABEL[expected_label]
    verdict = analysis.get("verdict") if analysis else ""
    # An analyzer may explicitly return null; treat it as absent evidence.
    model = (analysis.get("model_result") or {}) if analysis else {}
    brand = (analysis.get("brand_features") or {}) if analysis else {}
    identity = (analysis.get("brand_identity") or {}) if analysis else {}
    rdap = (analysis.get("rdap_features") or {}) if analysis else {}
    coverage = (analysis.get("feature_vector_coverage") or {}) if analysis else {}
    correct = bool(verdict == expected_verdict)
    return {
        "analysis_status": "completed" if verdict in {"SAFE", "DANGEROUS"} else "no_valid_analysis",
        "raw_probability_phishing": model.get("raw_probability_phishing", "") if model else "",
        "raw_verdict": model.get("raw_verdict", "") if model else "",
        "index": index,
        "input_url": input_url,
        "input_domain": safe_domain(input_url),
        "expected_label": expected_label,
        "expected_verdict": expected_verdict,
        "actual_verdict": verdict,
        "correct": int(correct) if verdict in {"SAFE", "DANGEROUS"} else "",
        "browser_final_url": "",
        "page_title": "",
        "analysis_url": analysis.get("url") if analysis else "",
        "analysis_final_url": analysis.get("final_url") if analysis else "",
        "registrable_domain": analysis.get("registrable_domain") if analysis else "",
        "score": analysis.get("score") if analysis else "",
        "probability_phishing": model.get("probability_phishing") if model else "",
        "threshold": model.get("threshold") if model else "",
        "post_model_guard": (model.get("post_model_guard") or {}).get("id") if model else "",
        "fired_rule_count": model.get("fired_rule_count") if model else "",
        "brand_name": (brand.get("brand_candidate_name") or brand.get("brand_top_candidate_name") or
                       (brand.get("claimed_brand") or {}).get("name")) if brand else "",
        "brand_domain": (brand.get("brand_candidate_domain") or brand.get("brand_top_candidate_domain") or
                         (brand.get("claimed_brand") or {}).get("official_domain")) if brand else "",
        "brand_identity_status": (identity.get("status") or brand.get("claimed_brand_status") or "") if identity or brand else "",
        "brand_identity_active_domain": identity.get("active_domain", "") if identity else "",
        "brand_identity_candidate_domain": identity.get("candidate_domain", "") if identity else "",
        "brand_identity_method": identity.get("discovery_method", "") if identity else "",
        "brand_identity_hostname_claim": identity.get("hostname_claim", "") if identity else "",
        "brand_identity_title_claim": identity.get("title_claim", "") if identity else "",
        "brand_identity_credential_form": identity.get("credential_form_observed", "") if identity else "",
        "brand_identity_fallback_status": identity.get("domain_fallback_status", "") if identity else "",
        "brand_identity_page_claim_domain": identity.get("page_claim_candidate_domain", "") if identity else "",
        "brand_identity_page_claim_name": identity.get("page_claim_candidate_name", "") if identity else "",
        "source_domain_age_days": rdap.get("source_domain_age_days") if rdap else "",
        "page_domain_age_days": rdap.get("page_domain_age_days") if rdap else "",
        "feature_coverage_percent": coverage.get("coverage_percent") if coverage else "",
        "reasons": compact_reasons(analysis),
        "displayed_reasons": " | ".join((analysis.get("explanation") or {}).get("reasons") or []) if analysis else "",
        "error": error,
    }


async def evaluate(args):
    if not args.isolated_per_url:
        raise ValueError('Validated evaluator requires --isolated-per-url')
    if not 1 <= args.parallel <= 2:
        raise ValueError('--parallel must be 1 or 2; keep resource use and API traffic bounded')
    if args.parallel > 1 and args.stop_after_evaluated:
        raise ValueError('--stop-after-evaluated requires --parallel 1')
    input_path = Path(args.input)
    extension_dir = Path(args.extension_dir).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((extension_dir / 'manifest.json').read_text(encoding='utf-8'))
    xgboost_model = extension_dir / 'src' / 'model' / 'xgboost-url18.json'
    use_xgboost = manifest.get('name', '').startswith('HeuriShield URL18 XGBoost') and xgboost_model.is_file()
    history_db = Path(args.history_db) if args.history_db else (
        Path(__file__).resolve().parents[2] / "hasil" / "database_evaluasi" / "riwayat_analisis.sqlite" if use_xgboost else None)
    fingerprints = {str(f.relative_to(extension_dir)): hashlib.sha256(f.read_bytes()).hexdigest()
                    for f in extension_dir.rglob('*') if f.is_file()
                    and (f.suffix == '.js' or f.name == 'manifest.json'
                         or f.name.startswith(('rulefit-engine-', 'feature-contract-')) and f.suffix == '.json'
                         or f == xgboost_model)
                    and '.git' not in f.parts and 'node_modules' not in f.parts}
    # Simpan engine yang benar-benar dipakai agar replay fitur tetap bisa dilakukan
    # meskipun isi folder extension berubah setelah pengujian.
    engine_path = xgboost_model if use_xgboost else extension_dir / 'src' / 'rule' / 'rulefit-engine-60.json'
    snapshot_path = out_dir / f'model_snapshot_{engine_path.name}'
    shutil.copyfile(engine_path, snapshot_path)
    (out_dir / 'run_manifest.json').write_text(json.dumps({
        'extension_dir': str(extension_dir), 'extension_version': manifest.get('version'),
        'file_hashes': fingerprints,
        'model_snapshot': snapshot_path.name,
        'evaluator_version': 'isolated-observed-warning-v5', 'parallel': args.parallel,
        'ignore_https_errors': args.ignore_https_errors,
        'navigation_wait_until': args.navigation_wait_until,
        'navigation_timeout_ms': args.navigation_timeout_ms,
        'analysis_timeout_ms': args.analysis_timeout_ms,
        'input_sha256': hashlib.sha256(input_path.read_bytes()).hexdigest()
    }, indent=2), encoding='utf-8')

    urls = read_urls(input_path)
    if args.shuffle:
        rng = random.Random(args.random_seed)
        rng.shuffle(urls)
    if args.start_index > 1:
        urls = urls[args.start_index - 1 :]
    if args.limit:
        urls = urls[: args.limit]

    if not urls:
        raise SystemExit(f"No URLs found in {input_path}")

    rows: list[dict] = []

    async with async_playwright() as p:
        launch_args = [
            f"--disable-extensions-except={extension_dir}",
            f"--load-extension={extension_dir}",
            "--disable-popup-blocking",
            "--no-first-run",
            "--no-default-browser-check",
        ]
        launch_options = {
            "headless": False,
            "args": launch_args,
            "viewport": {"width": 1280, "height": 900},
            "ignore_https_errors": args.ignore_https_errors,
        }
        if args.browser_executable:
            launch_options["executable_path"] = args.browser_executable

        if args.isolated_per_url:
            print(f"[browser-live] mode=isolated_per_url (1 browser/profile per URL; parallel={args.parallel})", flush=True)

            async def evaluate_and_record(index, url):
                started = time.monotonic()
                row = await evaluate_one_url_isolated(p, args, launch_options, out_dir, url, index)
                row["elapsed_seconds"] = round(time.monotonic() - started, 2)
                rows.append(row)
                status = "OK" if row["correct"] else "MISS"
                print(f"[{index}/{args.start_index + len(urls) - 1}] {status} {row['expected_label']} -> {row['actual_verdict'] or 'NO_ANALYSIS'} ({row['elapsed_seconds']}s) {url}", flush=True)
                if args.checkpoint_every and len(rows) % args.checkpoint_every == 0:
                    checkpoint_path = out_dir / "browser_live_rows.partial.csv"
                    write_csv(checkpoint_path, sorted(rows, key=lambda item: item["index"]), OUTPUT_FIELDS)
                    # Import a checkpoint every 25 URLs so a laptop interruption
                    # does not lose all structured evidence from the run.
                    if history_db and len(rows) % max(25, args.checkpoint_every) == 0:
                        try:
                            consolidate_live_analysis(out_dir)
                            import_report(history_db, out_dir)
                            print(f"[browser-live] database checkpoint: {len(rows)} URLs", flush=True)
                        except Exception as exc:
                            print(f"[browser-live] database checkpoint failed: {exc}", flush=True)
                return row

            if args.parallel == 1:
                for offset, url in enumerate(urls, start=0):
                    index = args.start_index + offset
                    await evaluate_and_record(index, url)
                    if args.stop_after_evaluated:
                        evaluated_count = sum(1 for item in rows if item.get("actual_verdict"))
                        if evaluated_count >= args.stop_after_evaluated:
                            print(f"[browser-live] stop_after_evaluated reached: {evaluated_count}", flush=True)
                            break
            else:
                semaphore = asyncio.Semaphore(args.parallel)

                async def bounded(index, url):
                    async with semaphore:
                        return await evaluate_and_record(index, url)

                await asyncio.gather(*(bounded(args.start_index + offset, url)
                    for offset, url in enumerate(urls)))
            rows.sort(key=lambda item: item["index"])
    expected_verdict = VERDICT_BY_LABEL[args.label]
    # Halaman warning yang terlihat tanpa analisis lengkap adalah observasi UI,
    # bukan prediksi model terverifikasi untuk menghitung akurasi.
    evaluated = [row for row in rows if row.get("analysis_status") == "completed"
                 and row["actual_verdict"]]
    correct = [row for row in evaluated if row["actual_verdict"] == expected_verdict]
    incorrect = [row for row in evaluated if row["actual_verdict"] != expected_verdict]
    no_analysis = [row for row in rows if row.get("analysis_status") != "completed"
                   or not row["actual_verdict"]]
    status_counts = dict(sorted(Counter(
        row.get("analysis_status") or "unknown" for row in rows).items()))
    http_error_codes = {}
    raw_path = out_dir / "browser_live_raw_analysis.jsonl"
    if raw_path.exists():
        for line in raw_path.read_text(encoding="utf-8").splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if item.get("analysis_status") != "http_error":
                continue
            codes = [code for response_url, code in (item.get("document_status") or {}).items()
                     if not is_warning_url(response_url) and isinstance(code, int) and code >= 400]
            if codes:
                key = str(codes[-1])
                http_error_codes[key] = http_error_codes.get(key, 0) + 1

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "chrome_extension_browser_live",
        "input": str(input_path),
        "label": args.label,
        "expected_verdict": expected_verdict,
        "total_urls": len(rows),
        "evaluated": len(evaluated),
        "correct": len(correct),
        "incorrect": len(incorrect),
        "no_analysis": len(no_analysis),
        "warning_page_observed": sum(row.get("analysis_status") == "warning_page_observed" for row in rows),
        "analysis_status_counts": status_counts,
        "response_category_counts": dict(sorted(Counter(row.get("response_category") or "unknown" for row in rows).items())),
        "no_analysis_reason_counts": dict(sorted(Counter(row.get("no_analysis_reason") or "unknown" for row in no_analysis).items())),
        "redirect_category_counts": dict(sorted(Counter(row.get("redirect_category") or "unknown" for row in rows).items())),
        "http_error_codes": dict(sorted(http_error_codes.items())),
        "model_analysis_count": sum(row.get("analysis_status") == "completed" for row in rows),
        "brand_identity_status_counts": dict(sorted(Counter(
            row.get("brand_identity_status") or "unavailable" for row in evaluated).items())),
        "brand_identity_guard_count": sum(
            row.get("post_model_guard") in {"BRAND_IDENTITY_MISMATCH_GUARD", "BRAND_LOOKALIKE_MODEL_GUARD"}
            for row in evaluated),
        "evaluation_definition": "Only completed model analyses with observed verdicts count toward accuracy; warning_page_observed is reported separately.",
        "accuracy_on_evaluated_percent": round((len(correct) / len(evaluated) * 100) if evaluated else 0, 2),
        "coverage_percent": round(len(evaluated) / len(rows) * 100, 2) if rows else 0,
    }

    write_csv(out_dir / "browser_live_rows.csv", rows, OUTPUT_FIELDS)
    write_csv(out_dir / "browser_live_incorrect.csv", incorrect, OUTPUT_FIELDS)
    write_csv(out_dir / "browser_live_no_analysis.csv", no_analysis, OUTPUT_FIELDS)
    (out_dir / "browser_live_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    audit_path = consolidate_live_analysis(out_dir)
    print(f"[browser-live] audit JSON: {audit_path}", flush=True)
    if history_db:
        try:
            run_id, saved = import_report(history_db, out_dir)
            print(f"[browser-live] database: {history_db} (run={run_id}; records={saved})", flush=True)
        except Exception as exc:
            print(f"[browser-live] database import failed; audit JSON remains available: {exc}", flush=True)
    print(json.dumps(summary, indent=2, ensure_ascii=False), flush=True)


async def evaluate_one_url_isolated(p, args, launch_options: dict, out_dir: Path, url: str, index: int) -> dict:
    if args.keep_profile:
        user_data_dir = out_dir / "profiles" / f"profile-{index:05d}"
        user_data_dir.mkdir(parents=True, exist_ok=True)
    else:
        user_data_dir = Path(tempfile.mkdtemp(prefix=f"heurishield-live-url-{index:05d}-"))

    context = None
    page = None
    raw_record_written = False
    document_status = {}
    try:
        context = await p.chromium.launch_persistent_context(str(user_data_dir), **launch_options)
        page = context.pages[0] if context.pages else await context.new_page()
        worker = await ensure_extension_worker(context, page)
        extension_id = worker.url.split("/")[2]
        await extension_set_storage(worker, {
            "heurishieldEnabled": True,
            "analysisByTab": {},
            "urlHistory": [],
            "featureArchive": [],
            "warningContexts": {},
            "heurishieldAllowlist": [],
            "heurishieldBlacklist": [],
        })

        started_at_ms = int(time.time() * 1000)
        tabs = await worker.evaluate('async () => await chrome.tabs.query({})')
        page_tabs = [t for t in tabs if t.get('url') == page.url]
        if len(page_tabs) != 1:
            raise RuntimeError('Cannot uniquely identify test tab')
        tab_id = page_tabs[0]['id']
        error = ""
        document_status = {}
        def record_response(response):
            if response.request.is_navigation_request() and response.frame == page.main_frame:
                document_status[response.url] = response.status
        page.on('response', record_response)
        try:
            await page.goto(url, wait_until=args.navigation_wait_until, timeout=args.navigation_timeout_ms)
        except Exception as exc:
            error = str(exc).splitlines()[0][:500]

        try:
            browser_final_url = page.url
        except Exception:
            browser_final_url = ""

        analysis = await wait_for_analysis(worker, started_at_ms, args.analysis_timeout_ms,
            tab_id, url, page, extension_id, document_status.keys())
        browser_final_url = page.url
        page_title = ""
        if not is_warning_url(browser_final_url, extension_id):
            try:
                page_title = await page.title()
            except Exception:
                pass
        warning_context_state = "not_warning"
        warning_target_url = ""
        if is_warning_url(browser_final_url, extension_id):
            context_id = warning_context_id(browser_final_url)
            stored_warning_context = await warning_context(worker, context_id) if context_id else None
            warning_target_url = (stored_warning_context or {}).get('originalUrl') or ''
            warning_context_state = ("missing" if not stored_warning_context else
                                     "missing_analysis" if not isinstance(stored_warning_context.get('analysis'), dict) else
                                     "analysis_not_accepted" if not analysis else "analysis_accepted")
        status = 'completed' if analysis else 'no_valid_analysis'
        if analysis:
            final = analysis.get('final_url') or url
            http_status = next((code for response_url, code in reversed(list(document_status.items()))
                if comparable_analysis_url(response_url) == comparable_analysis_url(final)), None)
            title = page_title or str(analysis.get('title') or '')
            if http_status is not None and http_status >= 400:
                status = 'http_error'
            elif re.search(r'\b(?:404|403|500|502|503)\b|page not found|access denied|client challenge|just a moment|verify.*human|account suspended|site suspended', title, re.I):
                status = 'error_or_challenge_page'
            elif http_status is None:
                status = 'unverified_http_status'
        if status == 'no_valid_analysis' and observed_warning_verdict(browser_final_url, extension_id, document_status):
            status = 'warning_page_observed'
        site_status = last_site_http_status(document_status)
        category = response_category(site_status, page_title or str((analysis or {}).get('title') or ''))
        redirect = redirect_category(url, (analysis or {}).get('final_url') or warning_target_url or browser_final_url,
                                     is_warning_url(browser_final_url, extension_id) and not warning_target_url)
        issue = ("" if status == 'completed' else
                 "warning_without_verified_analysis" if status == 'warning_page_observed' else
                 category if category != 'page_loaded' else
                 "model_analysis_missing_after_page_load" if status == 'no_valid_analysis' else
                 status)
        # Preserve the evidence even when it is excluded from the accuracy denominator.
        with (out_dir / 'browser_live_raw_analysis.jsonl').open('a', encoding='utf-8') as f:
            f.write(json.dumps({'index':index,'input_url':url,'expected_label':args.label,
                'analysis_status':status,'document_status':document_status,
                'page_title':page_title,'analysis':analysis,
                'site_http_status':site_status,'response_category':category,
                'redirect_category':redirect,'warning_context_state':warning_context_state,
                'warning_target_url':warning_target_url,
                'no_analysis_reason':issue}, ensure_ascii=False)+'\n')
        raw_record_written = True
        row = row_from_analysis(index, url, args.label, analysis if status == 'completed' else None, error)
        if status == 'warning_page_observed':
            # UI warning without a complete model record is an observation,
            # never a verified classification or a correct prediction.
            row['observed_warning_verdict'] = 'DANGEROUS'
            row['actual_verdict'] = ''
            row['correct'] = ''
        row['analysis_status'] = status
        row['browser_final_url'] = browser_final_url
        row['page_title'] = page_title
        row['site_http_status'] = site_status
        row['response_category'] = category
        row['redirect_category'] = redirect
        row['warning_context_state'] = warning_context_state
        row['warning_target_url'] = warning_target_url
        row['no_analysis_reason'] = issue
        return row
    except Exception as exc:
        error = str(exc).splitlines()[0][:500]
        browser_final_url = ""
        if page is not None:
            try:
                browser_final_url = page.url
            except Exception:
                pass
        if not raw_record_written:
            with (out_dir / 'browser_live_raw_analysis.jsonl').open('a', encoding='utf-8') as f:
                f.write(json.dumps({'index': index, 'input_url': url,
                    'expected_label': args.label, 'analysis_status': 'no_valid_analysis',
                    'document_status': document_status, 'browser_final_url': browser_final_url,
                    'analysis': None, 'error': error}, ensure_ascii=False) + '\n')
        row = row_from_analysis(index, url, args.label, None, error)
        row['browser_final_url'] = browser_final_url
        return row
    finally:
        if context:
            await context.close()
        if not args.keep_profile:
            shutil.rmtree(user_data_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--label", required=True, choices=sorted(VERDICT_BY_LABEL))
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--history-db", default="", help="SQLite archive shared across runs; URL18 XGBoost uses its experiment database by default.")
    parser.add_argument("--extension-dir", default=str(Path(__file__).resolve().parents[2] / "extension" / "HeuriShield-URL18-XGBoost"))
    parser.add_argument("--browser-executable", default="")
    parser.add_argument("--navigation-timeout-ms", type=int, default=25000)
    parser.add_argument("--navigation-wait-until", choices=("domcontentloaded", "commit"),
                        default="domcontentloaded",
                        help="For slow-page diagnosis, commit waits only for the first response; model analysis must still complete.")
    parser.add_argument("--analysis-timeout-ms", type=int, default=30000)
    parser.add_argument("--ignore-https-errors", action="store_true",
                        help="Diagnostic only: bypass certificate errors; keep results separate from standard live evaluation.")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--start-index", type=int, default=1)
    parser.add_argument("--shuffle", action="store_true")
    parser.add_argument("--random-seed", type=int, default=1182026)
    parser.add_argument("--stop-after-evaluated", type=int, default=0)
    parser.add_argument("--checkpoint-every", type=int, default=1)
    parser.add_argument("--parallel", type=int, default=1,
                        help="Number of isolated browsers to test concurrently (1 or 2; default 1).")
    parser.add_argument("--keep-profile", action="store_true")
    parser.add_argument("--isolated-per-url", action="store_true", help="Open a fresh browser profile for every URL to avoid stale extension state.")
    args = parser.parse_args()
    asyncio.run(evaluate(args))


if __name__ == "__main__":
    main()
