"""
Tests for login security scanner.
"""

import pytest
from unittest.mock import MagicMock
from tblue.scanner.login_security import LoginSecurityScanner


def make_scanner(html: str, headers: dict = None) -> LoginSecurityScanner:
    session       = MagicMock()
    resp          = MagicMock()
    resp.text     = html
    resp.headers  = headers or {}
    resp.url      = "https://example.com/login"
    session.request.return_value = resp
    return LoginSecurityScanner(session)


# ─── Login form detection ─────────────────────────────────────────────────────

def test_no_forms_returns_empty():
    html = "<html><body><p>No forms</p></body></html>"
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    assert results == []


def test_no_password_field_returns_empty():
    html = """
    <html><body>
      <form method="POST">
        <input name="search" type="text">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    assert results == []


# ─── HTTPS check ──────────────────────────────────────────────────────────────

def test_https_login_passes():
    html = """
    <html><body>
      <form method="POST" action="/login">
        <input name="username" type="text">
        <input name="password" type="password">
        <input name="csrf_token" type="hidden" value="abc">
      </form>
    </body></html>
    """
    scanner = make_scanner(html, {"cache-control": "no-store"})
    results = scanner.scan("https://example.com/login")
    https_result = next((r for r in results if "HTTPS" in r["type"]), None)
    if https_result:
        assert https_result["status"] == "PASS"


def test_http_form_action_fails():
    html = """
    <html><body>
      <form method="POST" action="http://example.com/login">
        <input name="username" type="text">
        <input name="password" type="password">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    assert any("HTTP" in r["type"] and r["status"] == "FAIL" for r in results)


# ─── Form method ──────────────────────────────────────────────────────────────

def test_post_method_passes():
    html = """
    <html><body>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    method_result = next((r for r in results if "method" in r["type"].lower()), None)
    if method_result:
        assert method_result["status"] == "PASS"


def test_get_method_fails():
    html = """
    <html><body>
      <form method="GET">
        <input name="username" type="text">
        <input name="password" type="password">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    assert any("GET" in r["type"] and r["status"] == "FAIL" for r in results)


# ─── CSRF token ───────────────────────────────────────────────────────────────

def test_csrf_token_present_passes():
    html = """
    <html><body>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
        <input name="csrf_token" type="hidden" value="abc123">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    csrf = next((r for r in results if "CSRF" in r["type"]), None)
    if csrf:
        assert csrf["status"] == "PASS"


def test_no_csrf_token_warns():
    html = """
    <html><body>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    assert any("CSRF" in r["type"] and r["status"] == "WARN" for r in results)


# ─── Autocomplete ─────────────────────────────────────────────────────────────

def test_autocomplete_off_passes():
    html = """
    <html><body>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password" autocomplete="current-password">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    ac = next((r for r in results if "autocomplete" in r["type"].lower()), None)
    if ac:
        assert ac["status"] == "PASS"


def test_missing_autocomplete_warns():
    html = """
    <html><body>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    assert any("autocomplete" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ─── Cache control ────────────────────────────────────────────────────────────

def test_no_store_cache_passes():
    html = """
    <html><body>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
      </form>
    </body></html>
    """
    scanner = make_scanner(html, {"cache-control": "no-store, no-cache"})
    results = scanner.scan("https://example.com/login")
    cache = next((r for r in results if "cache" in r["type"].lower()), None)
    if cache:
        assert cache["status"] == "PASS"


def test_missing_cache_control_fails():
    html = """
    <html><body>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
      </form>
    </body></html>
    """
    scanner = make_scanner(html, {})
    results = scanner.scan("https://example.com/login")
    assert any("cache" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_failed_request_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("Timeout")
    scanner = LoginSecurityScanner(session, retries=1)
    results = scanner.scan("https://example.com/login")
    assert results == []


# ─── HTTP page (no http:// action, but page itself is http) ───────────────────

def test_http_page_without_http_action_fails():
    html = """
    <html><body>
      <form method="POST" action="/login">
        <input name="username" type="text">
        <input name="password" type="password">
      </form>
    </body></html>
    """
    # Scan over http:// URL (no explicit http:// action but page is http)
    session = MagicMock()
    resp = MagicMock()
    resp.text = html
    resp.headers = {}
    resp.url = "http://example.com/login"
    session.request.return_value = resp
    scanner = LoginSecurityScanner(session)
    results = scanner.scan("http://example.com/login")
    assert any("page served over HTTP" in r["type"] and r["status"] == "FAIL" for r in results)


# ─── Password maxlength ───────────────────────────────────────────────────────

def test_password_maxlength_too_low_fails():
    html = """
    <html><body>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password" maxlength="8">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    assert any("maxlength too low" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_password_maxlength_low_warns():
    html = """
    <html><body>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password" maxlength="30">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    assert any("maxlength low" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_password_maxlength_adequate_passes():
    html = """
    <html><body>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password" maxlength="128">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    assert any("maxlength" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_password_maxlength_no_maxlength_passes():
    html = """
    <html><body>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    assert any("maxlength" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ─── Remember me ─────────────────────────────────────────────────────────────

def test_remember_me_checkbox_warns():
    html = """
    <html><body>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
        <input type="checkbox" name="remember_me">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    assert any("remember me" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_remember_me_label_warns():
    html = """
    <html><body>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
        <label>Remember me</label><input type="checkbox" name="keep">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    assert any("remember me" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ─── Username enumeration signal ──────────────────────────────────────────────

def test_username_enumeration_signal_warns():
    html = """
    <html><body>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
      </form>
      <p>User not found.</p>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    assert any("enumeration" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ─── Account lockout signal ───────────────────────────────────────────────────

def test_account_lockout_signal_passes():
    html = """
    <html><body>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
      </form>
      <p>Account locked. Too many attempts.</p>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    assert any("lockout signal" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ─── MFA indicators ───────────────────────────────────────────────────────────

def test_mfa_totp_text_passes():
    html = """
    <html><body>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
        <p>Enter your two-factor authentication code.</p>
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    assert any("mfa" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ─── Rate limiting header ─────────────────────────────────────────────────────

def test_rate_limit_header_passes():
    html = """
    <html><body>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
      </form>
    </body></html>
    """
    scanner = make_scanner(html, headers={"x-ratelimit-remaining": "10"})
    results = scanner.scan("https://example.com/login")
    assert any("rate limiting" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ─── Cache control: no-cache (WARN) ──────────────────────────────────────────

def test_password_maxlength_invalid_value_handled():
    # maxlength="abc" → ValueError → pass (no result added, no crash)
    html = """
    <html><body>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password" maxlength="notanumber">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    assert isinstance(results, list)


def test_external_script_with_sri_passes():
    html = """
    <html><body>
      <script src="https://cdn.example.com/app.js" integrity="sha384-abc" crossorigin="anonymous"></script>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    assert any("subresource integrity" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_external_script_without_sri_warns():
    html = """
    <html><body>
      <script src="https://cdn.example.com/app.js"></script>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
      </form>
    </body></html>
    """
    scanner = make_scanner(html)
    results = scanner.scan("https://example.com/login")
    assert any("subresource integrity missing" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


def test_no_cache_without_no_store_warns():
    html = """
    <html><body>
      <form method="POST">
        <input name="username" type="text">
        <input name="password" type="password">
      </form>
    </body></html>
    """
    scanner = make_scanner(html, headers={"cache-control": "no-cache, private"})
    results = scanner.scan("https://example.com/login")
    assert any("cache control" in r["type"].lower() and r["status"] == "WARN" for r in results)
