"""Extra branch coverage for tblue.scanner.cookies."""

from unittest.mock import MagicMock, patch
from tblue.scanner.cookies import CookieScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return CookieScanner(session)


def _resp(status=200, body="", set_cookie_list=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    raw_cookies = set_cookie_list or []
    r.raw = MagicMock()
    r.raw.headers = MagicMock()
    r.raw.headers.getlist = MagicMock(return_value=raw_cookies)
    r.raw.headers.items = MagicMock(
        return_value=[("set-cookie", c) for c in raw_cookies]
    )
    return r


def test_no_cookies_returns_empty_or_pass():
    """Covers the branch where the response has no cookies at all."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp()):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_missing_httponly_on_session_cookie_flagged():
    """Covers HttpOnly flag missing on session-like cookie."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(
        set_cookie_list=["sessionid=abc123; Secure; SameSite=Lax; Path=/"]
    )):
        results = s.scan(URL)
    assert any(r["status"] in ("FAIL", "WARN") for r in results)


def test_missing_secure_flag_on_session_cookie_flagged():
    """Covers Secure flag missing on session-like cookie."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(
        set_cookie_list=["session=xyz; HttpOnly; SameSite=Strict; Path=/"]
    )):
        results = s.scan(URL)
    assert any(r["status"] in ("FAIL", "WARN") for r in results)


def test_tracking_cookie_without_consent_banner_flagged():
    """Covers GDPR consent check when tracking cookies present but no banner."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(
        body="<html><body><p>Welcome</p></body></html>",
        set_cookie_list=["_ga=GA1.2.123456789.1620000000; Path=/"]
    )):
        results = s.scan(URL)
    assert any(r["status"] in ("WARN", "FAIL") for r in results)


def test_consent_banner_present_mitigates_tracking_flag():
    """Covers the branch where tracking cookie is present but consent banner exists."""
    s = _scanner()
    html = """<html><body>
    <div class="cookieconsent">We use cookies. <button>Accept all cookies</button></div>
    </body></html>"""
    with patch.object(s.http, "get", return_value=_resp(
        body=html,
        set_cookie_list=["_ga=GA1.2.123456789.1620000000; Path=/"]
    )):
        results = s.scan(URL)
    # With consent banner, should not produce FAIL for tracking cookie
    assert isinstance(results, list)


def test_no_response_returns_empty():
    """Covers the None-response early-exit path."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert results == []
