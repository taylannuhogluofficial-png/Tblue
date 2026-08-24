"""Tests for BackForwardCacheSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.back_forward_cache_security import BackForwardCacheSecurityScanner


def _scanner():
    s = BackForwardCacheSecurityScanner.__new__(BackForwardCacheSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestAuthRestore:
    def test_auth_restored_on_pageshow_fails(self):
        s = _scanner()
        # _BFC_AUTH_RESTORE_RE: pageshow ... persisted ... localStorage ... token
        body = "window.addEventListener('pageshow', e => { if (e.persisted) { const tok = localStorage.getItem('token') } })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "bfcache_auth_state_restored" in types


class TestNavigationTracking:
    def test_navigation_timing_tracking_warns(self):
        s = _scanner()
        # _BFC_TRACKING_RE: getEntriesByType('navigation') ... fetch
        body = "const nav = performance.getEntriesByType('navigation')[0]\nfetch('/analytics', {body: nav.type})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "bfcache_navigation_tracking" in types


class TestFormRestore:
    def test_form_data_restored_warns(self):
        s = _scanner()
        # _BFC_FORM_RESTORE_RE: pageshow ... persisted ... form.
        body = "window.addEventListener('pageshow', e => { if (e.persisted) { const v = form.value } })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "bfcache_form_data_restored" in types


class TestNotUsed:
    def test_no_bfcache_events_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "back_forward_cache_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
