"""Tests for sensitive URL parameter detector."""

import pytest
from unittest.mock import MagicMock
from tblue.scanner.sensitive_params import SensitiveParamScanner, _check_url


# ── _check_url ────────────────────────────────────────────────────────────────

def test_check_url_finds_token():
    findings = _check_url("https://example.com/reset?token=abc123xyz")
    assert any(p == "token" for p, _, _ in findings)


def test_check_url_finds_api_key():
    findings = _check_url("https://example.com/api?api_key=sk-1234567890")
    assert any(p == "api_key" for p, _, _ in findings)


def test_check_url_finds_password():
    findings = _check_url("https://example.com/login?password=secret123")
    assert any(p == "password" for p, _, _ in findings)


def test_check_url_finds_access_token():
    findings = _check_url("https://example.com/callback?access_token=eyJhbGciOiJSUzI1Ni")
    assert any(p == "access_token" for p, _, _ in findings)


def test_check_url_ignores_short_value():
    findings = _check_url("https://example.com/page?key=ab")
    assert findings == []


def test_check_url_clean_url_returns_empty():
    findings = _check_url("https://example.com/search?q=hello&page=2")
    assert findings == []


def test_check_url_case_insensitive_param():
    findings = _check_url("https://example.com/auth?API_KEY=12345678")
    assert any(p.lower() == "api_key" for p, _, _ in findings)


# ── scan_urls ─────────────────────────────────────────────────────────────────

def make_scanner():
    return SensitiveParamScanner(MagicMock())


def test_scan_urls_sensitive_param_warns():
    scanner = make_scanner()
    results = scanner.scan_urls(["https://example.com/reset?token=abcdef1234"])
    assert any("token" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_scan_urls_clean_passes():
    scanner = make_scanner()
    results = scanner.scan_urls(["https://example.com/page?q=hello"])
    assert any(r["status"] == "PASS" for r in results)


def test_scan_urls_multiple_params_all_flagged():
    scanner = make_scanner()
    urls = [
        "https://example.com/reset?token=abcdef1234",
        "https://example.com/api?api_key=sk-0987654321",
    ]
    results = scanner.scan_urls(urls)
    warns   = [r for r in results if r["status"] == "WARN"]
    assert len(warns) >= 2


def test_scan_urls_deduplicates():
    scanner = make_scanner()
    # Same param in same URL twice in list
    results = scanner.scan_urls([
        "https://example.com/r?token=abcdef1234",
        "https://example.com/r?token=abcdef1234",
    ])
    token_warns = [r for r in results if "token" in r["type"].lower() and r["status"] == "WARN"]
    assert len(token_warns) == 1


def test_scan_single_url_delegates():
    scanner = make_scanner()
    results = scanner.scan("https://example.com/auth?password=mysecret123")
    assert any("password" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_warn_result_has_fix_guidance():
    scanner = make_scanner()
    results = scanner.scan_urls(["https://example.com/r?token=abcdef1234"])
    warn    = next(r for r in results if r["status"] == "WARN")
    assert "fix" in warn["detail"].lower()
    assert "header" in warn["detail"].lower() or "post" in warn["detail"].lower()
