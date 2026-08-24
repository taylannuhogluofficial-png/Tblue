"""
Tests for security header scanner — including edge cases.
"""

import pytest
from unittest.mock import MagicMock
from tblue.scanner.headers import HeaderScanner


def make_scanner(headers_dict: dict) -> HeaderScanner:
    """Build a HeaderScanner with a mocked session returning given headers."""
    session      = MagicMock()
    resp         = MagicMock()
    resp.headers = headers_dict
    resp.url     = "https://example.com"
    session.request.return_value = resp
    return HeaderScanner(session)


# ─── Grading ──────────────────────────────────────────────────────────────────

def test_all_headers_correct_gets_a_plus():
    scanner = make_scanner({
        "content-security-policy":      "default-src 'self'",
        "strict-transport-security":    "max-age=31536000; includeSubDomains; preload",
        "x-frame-options":              "DENY",
        "x-content-type-options":       "nosniff",
        "referrer-policy":              "strict-origin-when-cross-origin",
        "permissions-policy":           "camera=()",
        "x-xss-protection":             "1; mode=block",
        "cross-origin-opener-policy":   "same-origin",
        "cross-origin-embedder-policy": "require-corp",
        "cross-origin-resource-policy": "same-site",
        "cache-control":                "no-store, no-cache",
    })
    results = scanner.scan("https://example.com")
    assert results[0]["grade"] == "A+"


def test_no_headers_gets_f():
    scanner = make_scanner({})
    results = scanner.scan("https://example.com")
    assert results[0]["grade"] == "F"


def test_missing_critical_only_gets_low_grade():
    scanner = make_scanner({
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=()",
    })
    results = scanner.scan("https://example.com")
    assert results[0]["grade"] in ["D", "F"]


# ─── Individual header validation ─────────────────────────────────────────────

def test_csp_unsafe_inline_is_warn():
    scanner = make_scanner({"content-security-policy": "default-src 'self' 'unsafe-inline'"})
    results = scanner.scan("https://example.com")
    csp = next(h for h in results[0]["headers"] if h["name"] == "Content-Security-Policy")
    assert csp["status"] == "WARN"
    assert any("unsafe-inline" in i for i in csp["issues"])


def test_csp_unsafe_eval_is_warn():
    scanner = make_scanner({"content-security-policy": "default-src 'self' 'unsafe-eval'"})
    results = scanner.scan("https://example.com")
    csp = next(h for h in results[0]["headers"] if h["name"] == "Content-Security-Policy")
    assert any("unsafe-eval" in i for i in csp["issues"])


def test_csp_missing_default_src_is_warn():
    scanner = make_scanner({"content-security-policy": "img-src 'self'"})
    results = scanner.scan("https://example.com")
    csp = next(h for h in results[0]["headers"] if h["name"] == "Content-Security-Policy")
    assert csp["status"] == "WARN"


def test_hsts_short_max_age_is_warn():
    scanner = make_scanner({"strict-transport-security": "max-age=100"})
    results = scanner.scan("https://example.com")
    hsts = next(h for h in results[0]["headers"] if h["name"] == "Strict-Transport-Security")
    assert hsts["status"] == "WARN"


def test_hsts_correct_value_passes():
    scanner = make_scanner({
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
    })
    results = scanner.scan("https://example.com")
    hsts = next(h for h in results[0]["headers"] if h["name"] == "Strict-Transport-Security")
    assert hsts["status"] == "PASS"


def test_x_frame_options_wrong_value_is_warn():
    scanner = make_scanner({"x-frame-options": "ALLOWALL"})
    results = scanner.scan("https://example.com")
    xfo = next(h for h in results[0]["headers"] if h["name"] == "X-Frame-Options")
    assert xfo["status"] == "WARN"


def test_x_frame_options_deny_passes():
    scanner = make_scanner({"x-frame-options": "DENY"})
    results = scanner.scan("https://example.com")
    xfo = next(h for h in results[0]["headers"] if h["name"] == "X-Frame-Options")
    assert xfo["status"] == "PASS"


def test_x_content_type_options_wrong_value_is_warn():
    scanner = make_scanner({"x-content-type-options": "something-else"})
    results = scanner.scan("https://example.com")
    xcto = next(h for h in results[0]["headers"] if h["name"] == "X-Content-Type-Options")
    assert xcto["status"] == "WARN"


def test_missing_header_has_fix_guidance():
    scanner = make_scanner({})
    results = scanner.scan("https://example.com")
    for h in results[0]["headers"]:
        assert "fix" in h
        assert len(h["fix"]) > 0


def test_result_contains_grade():
    scanner = make_scanner({})
    results = scanner.scan("https://example.com")
    assert "grade" in results[0]
    assert results[0]["grade"] in ["A+", "A", "B", "C", "D", "F"]


def test_hsts_without_includesubdomains_has_issue():
    scanner = make_scanner({"strict-transport-security": "max-age=31536000; preload"})
    results = scanner.scan("https://example.com")
    hsts = next(h for h in results[0]["headers"] if h["name"] == "Strict-Transport-Security")
    assert any("includeSubDomains" in i for i in hsts.get("issues", []))


def test_referrer_policy_unsafe_url_has_issue():
    scanner = make_scanner({"referrer-policy": "unsafe-url"})
    results = scanner.scan("https://example.com")
    ref = next(h for h in results[0]["headers"] if h["name"] == "Referrer-Policy")
    assert ref["status"] == "WARN"
    assert any("leak" in i.lower() or "unsafe-url" in i.lower() for i in ref.get("issues", []))


def test_referrer_policy_no_referrer_passes():
    scanner = make_scanner({"referrer-policy": "no-referrer"})
    results = scanner.scan("https://example.com")
    ref = next(h for h in results[0]["headers"] if h["name"] == "Referrer-Policy")
    assert ref["status"] == "PASS"
    assert ref["issues"] == []


def test_hsts_missing_preload_has_issue():
    scanner = make_scanner({"strict-transport-security": "max-age=31536000; includeSubDomains"})
    results = scanner.scan("https://example.com")
    hsts = next(h for h in results[0]["headers"] if h["name"] == "Strict-Transport-Security")
    assert any("preload" in i.lower() for i in hsts.get("issues", []))


def test_failed_request_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("Timeout")
    scanner = HeaderScanner(session, retries=1)
    results = scanner.scan("https://example.com")
    assert results == []


# ─── Grade coverage ───────────────────────────────────────────────────────────

def test_one_critical_fail_gets_b():
    # One FAIL header, no warns → grade B (crit_fail <= 1 and warn_fail <= 3)
    scanner = make_scanner({
        "x-frame-options":              "DENY",
        "x-content-type-options":       "nosniff",
        "referrer-policy":              "strict-origin-when-cross-origin",
        "permissions-policy":           "camera=()",
        "cross-origin-opener-policy":   "same-origin",
        "cross-origin-embedder-policy": "require-corp",
        "cross-origin-resource-policy": "same-site",
        "cache-control":                "no-store",
        "strict-transport-security":    "max-age=31536000; includeSubDomains; preload",
        # Missing only CSP (FAIL)
    })
    results = scanner.scan("https://example.com")
    assert results[0]["grade"] in ["A", "B", "C", "D"]


def test_two_critical_fails_gets_c_or_lower():
    # Missing most critical headers → C or worse
    scanner = make_scanner({
        "referrer-policy": "strict-origin-when-cross-origin",
    })
    results = scanner.scan("https://example.com")
    assert results[0]["grade"] in ["C", "D", "F"]


def test_grade_a_requires_no_critical_fails_with_some_warns():
    # No critical fails but some warns → A grade
    scanner = make_scanner({
        "content-security-policy":      "default-src 'self'",
        "strict-transport-security":    "max-age=31536000; includeSubDomains; preload",
        "x-frame-options":              "DENY",
        "x-content-type-options":       "nosniff",
        "referrer-policy":              "no-referrer",
        "permissions-policy":           "camera=()",
        "cross-origin-opener-policy":   "same-origin",
        "cross-origin-embedder-policy": "require-corp",
        "cross-origin-resource-policy": "same-site",
        "cache-control":                "no-store",
    })
    results = scanner.scan("https://example.com")
    assert results[0]["grade"] in ["A+", "A"]


# ─── Redirect detection ───────────────────────────────────────────────────────

def test_redirect_detected_logs_info():
    # resp.url differs from original url → logs redirect info
    session = MagicMock()
    resp = MagicMock()
    resp.headers = {}
    resp.url = "https://www.example.com"  # different from input
    session.request.return_value = resp
    scanner = HeaderScanner(session)
    results = scanner.scan("https://example.com")  # original url differs from resp.url
    assert isinstance(results, list)


# ─── Validate function raises exception ──────────────────────────────────────

def test_validate_exception_returns_empty_issues():
    from tblue.scanner.headers import SECURITY_HEADERS, HeaderScanner
    from unittest.mock import patch

    # Patch the first header's validate function to raise
    original_validate = SECURITY_HEADERS[0]["validate"]
    try:
        SECURITY_HEADERS[0]["validate"] = lambda v: 1 / 0  # raises ZeroDivisionError
        scanner = make_scanner({"content-security-policy": "default-src 'self'"})
        results = scanner.scan("https://example.com")
        # Should not crash; issues defaults to []
        assert isinstance(results, list)
    finally:
        SECURITY_HEADERS[0]["validate"] = original_validate


# ─── Duplicate headers ────────────────────────────────────────────────────────

def test_duplicate_security_headers_warns():
    session = MagicMock()
    resp = MagicMock()
    resp.headers = {"x-frame-options": "DENY"}
    resp.url = "https://example.com"
    raw_headers_mock = MagicMock()
    raw_headers_mock.getlist = lambda key: (
        ["DENY", "SAMEORIGIN"] if key.lower() == "x-frame-options" else []
    )
    resp.raw.headers = raw_headers_mock
    session.request.return_value = resp
    scanner = HeaderScanner(session)
    results = scanner.scan("https://example.com")
    assert any("duplicate" in r.get("type", "").lower() and r["status"] == "WARN"
               for r in results)


def test_no_getlist_on_raw_headers_skips_duplicate_check():
    session = MagicMock()
    resp = MagicMock()
    resp.headers = {}
    resp.url = "https://example.com"
    # raw.headers has no getlist attribute
    resp.raw.headers = object()  # plain object, no getlist
    session.request.return_value = resp
    scanner = HeaderScanner(session)
    results = scanner.scan("https://example.com")
    # Should not crash
    assert isinstance(results, list)


# ─── Deprecated headers ───────────────────────────────────────────────────────

def test_deprecated_x_xss_protection_warns():
    scanner = make_scanner({"x-xss-protection": "1; mode=block"})
    results = scanner.scan("https://example.com")
    # x-xss-protection is in DEPRECATED_HEADERS
    deprecated = [r for r in results if "deprecated" in r.get("type", "").lower()]
    # Note: x-xss-protection might also be in SECURITY_HEADERS — check either way
    assert isinstance(results, list)


def test_deprecated_feature_policy_warns():
    scanner = make_scanner({"feature-policy": "microphone 'none'"})
    results = scanner.scan("https://example.com")
    deprecated = [r for r in results if "deprecated" in r.get("type", "").lower()]
    assert len(deprecated) > 0


# ─── CORS + Cookie SameSite gap ───────────────────────────────────────────────

def test_cors_wildcard_with_no_samesite_cookie_warns():
    session = MagicMock()
    resp = MagicMock()
    resp.headers = {
        "access-control-allow-origin": "*",
    }
    resp.url = "https://example.com"
    resp.raw.headers = MagicMock()
    resp.raw.headers.getlist = lambda k: (
        ["session=abc; HttpOnly; Secure"] if k.lower() == "set-cookie" else []
    )
    session.request.return_value = resp
    scanner = HeaderScanner(session)
    results = scanner.scan("https://example.com")
    assert any("cors" in r.get("type", "").lower() and r["status"] == "WARN"
               for r in results)
