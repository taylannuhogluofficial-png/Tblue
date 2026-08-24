"""Tests for form and authentication security scanner."""

from unittest.mock import MagicMock
from tblue.scanner.form_security import FormSecurityScanner


def _scanner(html="", headers=None, status=200):
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = status
    resp.text = html
    resp.headers = headers or {}
    session.request.return_value = resp
    return FormSecurityScanner(session)


# ── CSRF ──────────────────────────────────────────────────────────────────────

def test_csrf_token_present_passes():
    html = ('<form method="post"><input type="hidden" name="csrf_token" value="abc">'
            '<input type="submit"></form>')
    scanner = _scanner(html=html)
    results = scanner._csrf_results(html, "https://example.com")
    assert any("csrf" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_csrf_token_missing_warns():
    html = '<form method="post"><input type="text" name="email"><input type="submit"></form>'
    scanner = _scanner(html=html)
    results = scanner._csrf_results(html, "https://example.com")
    assert any("csrf" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_get_form_not_flagged():
    html = '<form method="get"><input type="text" name="q"></form>'
    scanner = _scanner(html=html)
    results = scanner._csrf_results(html, "https://example.com")
    assert results == []


def test_xsrf_token_name_accepted():
    html = '<form method="post"><input type="hidden" name="xsrf_token" value="xyz"></form>'
    scanner = _scanner(html=html)
    results = scanner._csrf_results(html, "https://example.com")
    assert any("csrf" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_authenticity_token_accepted():
    html = '<form method="post"><input type="hidden" name="authenticity_token" value="xyz"></form>'
    scanner = _scanner(html=html)
    results = scanner._csrf_results(html, "https://example.com")
    assert any("csrf" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ── Password fields ───────────────────────────────────────────────────────────

def test_autocomplete_off_warns():
    html = '<input type="password" autocomplete="off">'
    scanner = _scanner(html=html)
    results = scanner._password_results(html, "https://example.com")
    assert any("password manager" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_no_autocomplete_off_passes():
    html = '<input type="password" name="password">'
    scanner = _scanner(html=html)
    results = scanner._password_results(html, "https://example.com")
    assert any("password" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ── Cache-Control on sensitive pages ─────────────────────────────────────────

def test_no_store_on_account_passes():
    headers = {"Cache-Control": "no-store"}
    scanner = _scanner(headers=headers)
    scanner._check_cache_control(headers, "https://example.com/account/settings")
    assert any("not cached" in r["type"].lower() and r["status"] == "PASS"
               for r in scanner.results)


def test_missing_no_store_on_account_warns():
    headers = {"Cache-Control": "public"}
    scanner = _scanner(headers=headers)
    scanner._check_cache_control(headers, "https://example.com/account/profile")
    assert any("cached" in r["type"].lower() and r["status"] == "WARN"
               for r in scanner.results)


def test_non_sensitive_page_skipped():
    headers = {}
    scanner = _scanner(headers=headers)
    scanner._check_cache_control(headers, "https://example.com/about")
    # Should not add any results for non-sensitive pages
    assert scanner.results == []


def test_private_cache_on_sensitive_page_warns():
    headers = {"Cache-Control": "private"}
    scanner = _scanner(headers=headers)
    scanner._check_cache_control(headers, "https://example.com/dashboard")
    # "caching could be stricter" — partial match on "cach"
    assert any("cach" in r["type"].lower() and r["status"] == "WARN" for r in scanner.results)


def test_no_cache_pragma_on_sensitive_page_warns():
    headers = {"Cache-Control": "", "Pragma": "no-cache"}
    scanner = _scanner(headers=headers)
    scanner._check_cache_control(headers, "https://example.com/payment")
    assert any("cach" in r["type"].lower() and r["status"] == "WARN" for r in scanner.results)


# ── .well-known/change-password ───────────────────────────────────────────────

def test_change_password_url_present_passes():
    scanner = _scanner(status=200)
    scanner._check_change_password_url("https://example.com")
    assert any("change-password" in r["type"].lower() and r["status"] == "PASS"
               for r in scanner.results)


def test_change_password_redirect_passes():
    scanner = _scanner(status=302)
    scanner._check_change_password_url("https://example.com")
    assert any("change-password" in r["type"].lower() and r["status"] == "PASS"
               for r in scanner.results)


def test_change_password_url_missing_warns():
    scanner = _scanner(status=404)
    scanner._check_change_password_url("https://example.com")
    assert any("change-password" in r["type"].lower() and r["status"] == "WARN"
               for r in scanner.results)


def test_change_password_request_returns_none_warns():
    # http.get() swallows exceptions and returns None; code treats None as missing → WARN
    session = MagicMock()
    session.request.return_value = None
    scanner = FormSecurityScanner(session)
    scanner._check_change_password_url("https://example.com")
    assert any("change-password" in r["type"].lower() and r["status"] == "WARN"
               for r in scanner.results)


# ── scan() integration ────────────────────────────────────────────────────────

def test_scan_with_no_forms_runs_cleanly():
    html = "<html><body><p>No forms here</p></body></html>"
    scanner = _scanner(html=html, headers={"Cache-Control": "public"})
    results = scanner.scan("https://example.com")
    assert isinstance(results, list)


def test_scan_exception_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("network error")
    scanner = FormSecurityScanner(session)
    results = scanner.scan("https://example.com")
    assert results == []


# ── scan_page() ────────────────────────────────────────────────────────────────

def test_scan_page_with_csrf_form():
    html = '<form method="post"><input name="csrf_token" value="x"></form>'
    scanner = _scanner(html=html)
    results = scanner.scan_page(html, "https://example.com/login")
    assert any("csrf" in r["type"].lower() for r in results)
