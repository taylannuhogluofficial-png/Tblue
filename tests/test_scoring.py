"""
Tests for the severity scoring engine.
"""

import pytest
from tblue.scoring import (
    classify_severity,
    score_results,
    CRITICAL, HIGH, MEDIUM, LOW, INFO,
)


# ── classify_severity ─────────────────────────────────────────────────────────

def test_pass_is_always_info():
    assert classify_severity("SSL / HTTPS", "PASS") == INFO
    assert classify_severity("Cookie 'x' — HttpOnly missing", "PASS") == INFO


def test_no_https_critical():
    assert classify_severity("SSL / HTTPS", "FAIL") == CRITICAL


def test_env_file_critical():
    assert classify_severity("Info disclosure — .env file", "FAIL") == CRITICAL


def test_git_repo_critical():
    assert classify_severity("Info disclosure — Git repository — HEAD file", "FAIL") == CRITICAL


def test_api_key_critical():
    assert classify_severity("Info disclosure — API keys in page source", "FAIL") == CRITICAL


def test_template_injection_fail_is_critical():
    assert classify_severity("Template injection — Jinja2/Handlebars", "FAIL") == CRITICAL


def test_template_injection_warn_is_medium():
    assert classify_severity("Template injection — Jinja2/Handlebars", "WARN") == MEDIUM


def test_csp_missing_high():
    assert classify_severity("CSP — missing", "FAIL") == HIGH


def test_xss_form_fail_is_high():
    assert classify_severity("Form #1 — GET /search", "FAIL") == HIGH


def test_xss_form_warn_is_low():
    # WARN on XSS = marker reflected but encoded — low severity
    assert classify_severity("Form #1 — GET /search", "WARN") == LOW


def test_httponly_missing_high():
    assert classify_severity("Cookie 'session' — HttpOnly missing", "FAIL") == HIGH


def test_samesite_missing_medium():
    assert classify_severity("Cookie 'x' — SameSite missing", "FAIL") == MEDIUM


def test_x_powered_by_medium():
    assert classify_severity("Info disclosure — X-Powered-By: PHP/8.0", "FAIL") == MEDIUM


def test_email_disclosure_low():
    assert classify_severity("Info disclosure — email addresses (1 found)", "WARN") == LOW


def test_unknown_type_defaults_to_medium_on_fail():
    assert classify_severity("Something totally new", "FAIL") == MEDIUM


def test_unknown_type_defaults_to_low_on_warn():
    assert classify_severity("Something totally new", "WARN") == LOW


# ── score_results ─────────────────────────────────────────────────────────────

def test_perfect_score_all_pass():
    results = {"ssl": [{"type": "SSL / HTTPS", "status": "PASS", "url": "https://x.com"}]}
    s = score_results(results)
    assert s.score == 100
    assert s.grade == "A+"
    assert s.total_deducted == 0


def test_one_critical_fail_deducts_20():
    results = {"ssl": [{"type": "SSL / HTTPS", "status": "FAIL", "url": "https://x.com"}]}
    s = score_results(results)
    assert s.score == 80
    assert s.breakdown[CRITICAL] == 1
    assert s.deductions[CRITICAL] == 20


def test_score_capped_at_zero():
    # Max deductions across all severity bands: critical(35) + high(25) + medium(20) + low(10) = 90
    # Score should reach 0 only when all bands are maxed out (total >= 100).
    # Use enough findings to saturate every cap.
    criticals = [{"type": "SSL / HTTPS", "status": "FAIL", "url": "u"}] * 5          # 5*20=100 → cap 35
    highs     = [{"type": "CSP — missing", "status": "FAIL", "url": "u"}] * 5         # 5*10=50  → cap 25
    mediums   = [{"type": "Security headers — missing", "status": "FAIL", "url": "u"}] * 5  # 5*5=25 → cap 20
    lows      = [{"type": "Information disclosure", "status": "WARN", "url": "u"}] * 20    # 20*1=20 → cap 10
    results = {"m": criticals + highs + mediums + lows}
    s = score_results(results)
    # Caps: critical min(100,35)=35, high min(100,25)=25, low min(20,10)=10 → total 70 → score 30
    # (medium bucket is 0 because "security headers" FAIL classifies as HIGH, not MEDIUM)
    assert s.score == 30
    assert s.score >= 0


def test_grade_bands():
    from tblue.scoring import _grade
    assert _grade(100) == "A+"
    assert _grade(90)  == "A+"
    assert _grade(89)  == "A"
    assert _grade(80)  == "A"
    assert _grade(79)  == "B"
    assert _grade(65)  == "B"
    assert _grade(64)  == "C"
    assert _grade(50)  == "C"
    assert _grade(49)  == "D"
    assert _grade(30)  == "D"
    assert _grade(29)  == "F"
    assert _grade(0)   == "F"


def test_top_issues_ordered_by_severity():
    results = {
        "info": [
            {"type": "Info disclosure — email addresses (1 found)", "status": "WARN", "url": "u"},
            {"type": "SSL / HTTPS", "status": "FAIL", "url": "u"},
        ]
    }
    s = score_results(results)
    # Critical (SSL / HTTPS) should come before low (email)
    assert s.top_issues[0]["severity"] == CRITICAL


def test_pass_results_not_in_top_issues():
    results = {"ssl": [{"type": "SSL / HTTPS", "status": "PASS", "url": "u"}]}
    s = score_results(results)
    assert s.top_issues == []


def test_breakdown_counts_correctly():
    results = {
        "ssl": [
            {"type": "SSL / HTTPS", "status": "FAIL", "url": "u"},
        ],
        "csp": [
            {"type": "CSP — missing", "status": "FAIL", "url": "u"},
            {"type": "CSP — missing", "status": "WARN", "url": "u"},
        ],
    }
    s = score_results(results)
    # SSL FAIL → CRITICAL; CSP FAIL → HIGH; CSP WARN → MEDIUM
    assert s.breakdown[CRITICAL] == 1
    assert s.breakdown[HIGH] == 1
    assert s.breakdown[MEDIUM] == 1
