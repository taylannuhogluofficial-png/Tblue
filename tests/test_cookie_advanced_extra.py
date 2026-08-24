"""Extra branch coverage for tblue.scanner.cookie_advanced."""

from unittest.mock import MagicMock, patch
from tblue.scanner.cookie_advanced import CookieAdvancedScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return CookieAdvancedScanner(session)


def _resp(status=200, body="", headers=None, set_cookie=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    # Build raw headers mock
    raw_cookies = set_cookie or []
    r.raw = MagicMock()
    r.raw.headers = MagicMock()
    r.raw.headers.items = MagicMock(
        return_value=[("set-cookie", c) for c in raw_cookies]
    )
    return r


def test_no_cookies_returns_pass():
    """Covers the branch where there are no Set-Cookie headers."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp()):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_secure_prefix_without_secure_flag_fails():
    """Covers __Secure- prefix cookie missing the Secure attribute."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(
        set_cookie=["__Secure-session=abc123; HttpOnly; SameSite=Strict"]
    )):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_host_prefix_without_secure_fails():
    """Covers __Host- prefix cookie without Secure flag."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(
        set_cookie=["__Host-token=xyz; HttpOnly; Path=/"]
    )):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_samesite_none_without_secure_warns():
    """Covers SameSite=None without Secure attribute detection branch."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(
        set_cookie=["session=abc; SameSite=None; HttpOnly"]
    )):
        results = s.scan(URL)
    assert any(r["status"] in ("WARN", "FAIL") for r in results)


def test_well_configured_cookie_returns_pass():
    """Covers the well-configured cookie path (all checks pass)."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(
        set_cookie=["session=abc; Secure; HttpOnly; SameSite=Strict; Path=/"]
    )):
        results = s.scan(URL)
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


def test_none_response_returns_empty_list():
    """Covers the None-response branch that returns early."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert results == []
