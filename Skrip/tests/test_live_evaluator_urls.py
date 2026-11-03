"""Regresi pencocokan URL evaluasi; tidak membuka browser atau jaringan."""
from __future__ import annotations

import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPT_DIR))
spec = importlib.util.spec_from_file_location("live_evaluator", SCRIPT_DIR / "evaluate-extension-browser-live.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_bare_host_matches_browser_slash() -> None:
    assert module.comparable_url("https://example.com") == module.comparable_url("https://example.com/")
    assert module.comparable_url("https://example.com?x=1") == module.comparable_url("https://example.com/?x=1")
    assert module.comparable_url("https://example.com/path#section") == "https://example.com/path"


def test_current_warning_analysis_accepts_normalized_input() -> None:
    now = datetime.now(timezone.utc)
    analysis = {
        "tab_id": 7,
        "analyzed_at": now.isoformat(),
        "url": "https://example.com/",
        "final_url": "https://example.com/",
        "verdict": "DANGEROUS",
        "model_result": {"ready": True},
    }
    started = int(now.timestamp() * 1000) - 1000
    assert module.valid_current_analysis(analysis, started, 7, "https://example.com",
                                          ["https://example.com/"])
    assert not module.valid_current_analysis(analysis, started, 7, "https://other.com",
                                              ["https://example.com/"])


def test_redacted_private_server_link_keeps_verified_analysis() -> None:
    now = datetime.now(timezone.utc)
    full = "https://www.roblox.com.ml/games/82681049019609/Anime-Girl-Fishing?privateServerLinkCode=384328757637766641742433182819"
    redacted = "https://www.roblox.com.ml/games/82681049019609/Anime-Girl-Fishing"
    analysis = {"tab_id": 7, "analyzed_at": now.isoformat(), "url": redacted,
                "final_url": redacted, "verdict": "DANGEROUS",
                "model_result": {"ready": True}}
    started = int(now.timestamp() * 1000) - 1000
    assert module.comparable_analysis_url(full) == redacted
    assert module.valid_current_analysis(analysis, started, 7, full, [full])
    assert not module.valid_current_analysis(analysis, started, 7, full,
                                             ["https://other.test/"])
    assert not module.valid_current_analysis(analysis, started, 8, full, [full])
    assert not module.valid_current_analysis(
        {**analysis, "url": redacted + "?view=other", "final_url": redacted + "?view=other"},
        started, 7, full, [full])
    shortener = "https://g5.lu/y2vkt"
    assert module.valid_current_analysis(analysis, started, 7, shortener,
                                         [shortener, full])
    assert module.comparable_analysis_url(full) == module.comparable_analysis_url(redacted)


def test_missing_analysis_is_not_a_wrong_prediction() -> None:
    row = module.row_from_analysis(1, "https://example.com/", "phishing", None)
    assert row["analysis_status"] == "no_valid_analysis"
    assert row["actual_verdict"] == ""
    assert row["correct"] == ""


def test_failure_categories_remain_distinct() -> None:
    assert module.response_category(403) == "http_403_denied"
    assert module.response_category(404) == "not_found"
    assert module.response_category(200, "Just a moment") == "access_challenge"
    assert module.response_category(200, "Site not found") == "not_found"
    assert module.redirect_category("https://a.test/path", "https://b.test/") == "cross_host"
    assert module.redirect_category("https://a.test/path", "", True) == "extension_warning"


if __name__ == "__main__":
    test_bare_host_matches_browser_slash()
    test_current_warning_analysis_accepts_normalized_input()
    test_redacted_private_server_link_keeps_verified_analysis()
    test_missing_analysis_is_not_a_wrong_prediction()
    test_failure_categories_remain_distinct()
    print("5 offline regression checks passed")
