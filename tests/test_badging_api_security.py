"""Tests for BadgingAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.badging_api_security import BadgingAPISecurityScanner


def _scanner():
    s = BadgingAPISecurityScanner.__new__(BadgingAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestCountFromParam:
    def test_badge_count_from_param_warns(self):
        s = _scanner()
        # _BAD_COUNT_FROM_PARAM_RE: setAppBadge(searchParams...)
        body = "navigator.setAppBadge(parseInt(searchParams.get('count')))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "badge_count_from_url_param" in types


class TestFromServer:
    def test_badge_from_server_response_warns(self):
        s = _scanner()
        # _BAD_FROM_SERVER_RE: fetch ... setAppBadge
        body = "fetch('/notifications').then(r => r.json()).then(data => navigator.setAppBadge(data.count))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "badge_controlled_by_server" in types


class TestAutoSet:
    def test_badge_auto_set_on_load_warns(self):
        s = _scanner()
        # _BAD_AUTO_SET_RE: DOMContentLoaded ... setAppBadge
        body = "window.addEventListener('DOMContentLoaded', () => navigator.setAppBadge(5))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "badge_auto_set_on_load" in types


class TestNotUsed:
    def test_no_badging_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "badging_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
