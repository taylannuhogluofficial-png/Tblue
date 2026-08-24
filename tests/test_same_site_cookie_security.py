"""Tests for SameSiteCookieSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.same_site_cookie_security import SameSiteCookieSecurityScanner


def _scanner():
    s = SameSiteCookieSecurityScanner.__new__(SameSiteCookieSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_same_site_none_without_secure():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.cookie = 'session=abc; SameSite=None; Path=/'"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "same_site_none_without_secure" in types


def test_same_site_lax_on_auth_cookie():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.cookie = 'authToken=xyz; SameSite=Lax; Secure; Path=/'"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "same_site_lax_on_auth_cookie" in types


def test_same_site_cookie_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.cookie = 'pref=' + searchParams.get('pref') + '; Path=/'"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "same_site_cookie_from_param" in types


def test_same_site_cookie_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No cookie configuration here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "same_site_cookie_not_used"
    assert results[0]["status"] == "PASS"


def test_same_site_cookie_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "same_site_cookie_not_used"
