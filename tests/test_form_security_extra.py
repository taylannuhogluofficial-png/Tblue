"""Extra coverage for form_security — lines 40-41 (exception in scan), 57-58 (scan_page exception), 163-164 (change-password PASS)."""

from unittest.mock import MagicMock, patch
from tblue.scanner.form_security import FormSecurityScanner

URL = "https://example.com/login"


def _make_scanner():
    return FormSecurityScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.__bool__ = lambda self: self.status_code < 400
    return r


# ── Exception in scan() (lines 40-41) ────────────────────────────────────────

def test_scan_exception_returns_empty():
    """Exception during http.get in scan() returns empty (lines 40-41 except path)."""
    s = _make_scanner()
    with patch.object(s.http, "get", side_effect=Exception("network timeout")):
        results = s.scan(URL)
    assert results == []


# ── scan_page exception (lines 57-58) ────────────────────────────────────────

def test_scan_page_exception_in_get_continues():
    """Exception in scan_page() http.get falls back to empty headers (lines 57-58)."""
    s = _make_scanner()
    html = "<html><body><form><input type='text' name='q'></form></body></html>"
    with patch.object(s.http, "get", side_effect=Exception("timeout")):
        results = s.scan_page(html, URL)
    # Must not raise — returns whatever CSRF/password checks produce
    assert isinstance(results, list)


# ── .well-known/change-password configured (lines 163-164) ──────────────────

def test_change_password_url_configured_passes():
    """/.well-known/change-password returning 200/3xx produces PASS (lines 163-164)."""
    s = _make_scanner()
    html = (
        "<html><body>"
        "<form method='post'>"
        "<input type='hidden' name='csrf_token' value='abc123'>"
        "<input type='text' name='username'>"
        "<input type='submit'>"
        "</form></body></html>"
    )

    def se(url, **kw):
        if "change-password" in url:
            return _resp(302, "", {"location": "https://example.com/settings/password"})
        return _resp(200, html)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    change_pw_results = [r for r in results if "change-password" in r["type"].lower()]
    assert any(r["status"] == "PASS" for r in change_pw_results), \
        f"Expected PASS for configured change-password URL: {change_pw_results}"


def test_change_password_url_missing_warns():
    """Missing /.well-known/change-password produces WARN."""
    s = _make_scanner()
    html = (
        "<html><body>"
        "<form method='post'>"
        "<input type='hidden' name='csrf_token' value='xyz'>"
        "<input type='text' name='username'>"
        "</form></body></html>"
    )

    def se(url, **kw):
        if "change-password" in url:
            return _resp(404)
        return _resp(200, html)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    change_pw_results = [r for r in results if "change-password" in r["type"].lower()]
    assert any(r["status"] == "WARN" for r in change_pw_results), \
        f"Expected WARN for missing change-password URL: {change_pw_results}"


# ── Exception in _check_change_password_url (lines 163-164) ──────────────────

def test_change_password_url_exception_is_caught():
    """Exception from http.get inside _check_change_password_url is caught (lines 163-164)."""
    s = _make_scanner()
    html = (
        "<html><body>"
        "<form method='post'>"
        "<input type='text' name='user'>"
        "<input type='password' name='pw'>"
        "</form></body></html>"
    )

    def se(url, **kw):
        if "change-password" in url:
            raise ConnectionError("host unreachable")  # caught by except Exception: pass
        return _resp(200, html)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    # Exception is caught → scan continues → results list returned without raising
    assert isinstance(results, list)
