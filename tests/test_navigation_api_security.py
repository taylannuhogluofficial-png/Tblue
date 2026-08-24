"""Tests for NavigationAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.navigation_api_security import NavigationAPISecurityScanner


def _scanner():
    s = NavigationAPISecurityScanner.__new__(NavigationAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestURLTransmitted:
    def test_nav_url_to_analytics_warns(self):
        s = _scanner()
        # _NAV_SEND_URL_RE: navigate ... destination.url (before) ... analytics (after, no ;)
        body = "window.navigation.addEventListener('navigate', event => { const url = event.destination.url\nanalytics('nav', {url: url}) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "navigation_api_url_transmitted" in types


class TestParamRedirect:
    def test_url_param_redirect_fails(self):
        s = _scanner()
        # _NAV_URL_PARAM_REDIRECT_RE: navigate ... searchParams ... navigate within bounds
        body = "window.navigation.addEventListener('navigate', e => { if (searchParams.get('to')) { navigate(searchParams.get('to')) } })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "navigation_api_param_redirect" in types


class TestInterceptAll:
    def test_intercept_all_warns(self):
        s = _scanner()
        body = "window.navigation.addEventListener('navigate', event => { event.intercept({handler: handleNav}) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "navigation_api_intercepts_all" in types


class TestNotUsed:
    def test_no_navigation_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "navigation_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
