"""Tests for CookieStoreSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.cookie_store_security import CookieStoreSecurityScanner


def _scanner():
    s = CookieStoreSecurityScanner.__new__(CookieStoreSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestValueFromParam:
    def test_cookie_value_from_param_fails(self):
        s = _scanner()
        # _CS_VALUE_FROM_PARAM_RE: cookieStore.set(searchParams...)
        body = "cookieStore.set('pref', searchParams.get('val'))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "cookie_store_value_from_url_param" in types


class TestEnumerateExfil:
    def test_all_cookies_exfiltrated_fails(self):
        s = _scanner()
        # _CS_ENUMERATE_EXFIL_RE: cookieStore.getAll() ... fetch
        body = "cookieStore.getAll().then(cookies => fetch('/steal', {body: JSON.stringify(cookies)}))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "cookie_store_all_cookies_exfiltrated" in types


class TestChangeEventExfil:
    def test_change_event_exfil_warns(self):
        s = _scanner()
        # _CS_CHANGE_EXFIL_RE: cookieStore.addEventListener('change' ... sendBeacon
        body = "cookieStore.addEventListener('change', e => sendBeacon('/log', JSON.stringify(e.changed)))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "cookie_store_change_event_exfil" in types


class TestNotUsed:
    def test_no_cookie_store_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "cookie_store_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
