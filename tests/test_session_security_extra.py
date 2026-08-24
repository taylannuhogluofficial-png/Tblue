"""Extra branch coverage for tblue.scanner.session_security."""

from unittest.mock import MagicMock, patch
from tblue.scanner.session_security import SessionSecurityScanner

URL = "https://example.com"


def _resp(body="", status=200, headers=None, cookies=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.url = URL
    r.cookies = cookies if cookies is not None else []
    return r


def _scanner():
    session = MagicMock()
    return SessionSecurityScanner(session)


def test_session_id_in_url_fails():
    """PHPSESSID in URL query string → FAIL."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html></html>", cookies=[])):
        results = s.scan(URL + "?PHPSESSID=abc123")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_jsessionid_in_url_fails():
    """jsessionid in URL → FAIL."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html></html>", cookies=[])):
        results = s.scan(URL + "?jsessionid=deadbeef1234567890")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_clean_url_no_session_params_passes():
    """Clean URL with no session params → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html></html>", cookies=[])):
        results = s.scan(URL + "?page=1")
    assert all(r["status"] != "FAIL" for r in results)


def test_login_form_get_method_fails():
    """Login form with GET method → FAIL."""
    s = _scanner()
    html = '<html><body><form action="/login" method="get"><input name="password"/></form></body></html>'
    with patch.object(s.http, "get", return_value=_resp(html, cookies=[])):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_none_response_no_fail():
    """None response → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert all(r["status"] != "FAIL" for r in results)
