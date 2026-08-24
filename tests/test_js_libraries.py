"""Tests for outdated JavaScript library detection."""

import pytest
from unittest.mock import MagicMock
from tblue.scanner.js_libraries import JSLibraryScanner, _ver_lt, _check_vuln


def make_scanner(html: str = "") -> JSLibraryScanner:
    session = MagicMock()
    resp    = MagicMock()
    resp.status_code = 200
    resp.text        = html
    resp.url         = "https://example.com"
    session.request.return_value = resp
    return JSLibraryScanner(session)


# ── _ver_lt ───────────────────────────────────────────────────────────────────

def test_ver_lt_older():
    assert _ver_lt("3.4.0", "3.5.0") is True


def test_ver_lt_same():
    assert _ver_lt("3.5.0", "3.5.0") is False


def test_ver_lt_newer():
    assert _ver_lt("3.6.0", "3.5.0") is False


def test_ver_lt_major_diff():
    assert _ver_lt("2.9.9", "3.0.0") is True


def test_ver_lt_minor_diff():
    assert _ver_lt("3.4.9", "3.5.0") is True


# ── _check_vuln ───────────────────────────────────────────────────────────────

def test_old_jquery_is_vuln():
    result = _check_vuln("jquery", "3.4.0")
    assert result is not None
    sev, cves = result
    assert sev == "HIGH"
    assert "CVE" in cves


def test_current_jquery_not_vuln():
    result = _check_vuln("jquery", "3.7.0")
    assert result is None


def test_old_bootstrap_is_vuln():
    result = _check_vuln("bootstrap", "3.3.7")
    assert result is not None


def test_unknown_lib_not_vuln():
    result = _check_vuln("react", "17.0.0")
    assert result is None


# ── Scanner detection via URL ─────────────────────────────────────────────────

def test_outdated_jquery_in_script_src_fails():
    html    = '<script src="/js/jquery-1.11.3.min.js"></script>'
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    assert any("jquery" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_outdated_bootstrap_in_script_src_warns():
    html    = '<script src="/js/bootstrap-3.3.0.min.js"></script>'
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    assert any("bootstrap" in r["type"].lower() and r["status"] in ("WARN", "FAIL")
               for r in results)


def test_current_jquery_passes():
    html    = '<script src="/js/jquery-3.7.1.min.js"></script>'
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)
    assert not any("fail" == r["status"].lower() for r in results)


def test_cdn_url_version_detected():
    html = '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>'
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    assert any("jquery" in r["type"].lower() and r["status"] == "FAIL" for r in results)


# ── Scanner detection via inline comment ──────────────────────────────────────

def test_inline_comment_version_detected():
    html    = '<script>/*! jQuery v1.8.3 | (c) 2012 jQuery Foundation */</script>'
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    assert any("jquery" in r["type"].lower() and r["status"] == "FAIL" for r in results)


# ── No libraries ──────────────────────────────────────────────────────────────

def test_no_js_libraries_passes():
    html    = '<html><body><p>Hello</p></body></html>'
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


# ── Error handling ────────────────────────────────────────────────────────────

def test_failed_request_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("Timeout")
    scanner = JSLibraryScanner(session, retries=1)
    results = scanner.scan("https://example.com")
    assert results == []
