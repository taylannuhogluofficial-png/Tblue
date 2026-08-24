"""Tests for SanitizerAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.sanitizer_api_security import SanitizerAPISecurityScanner


def _scanner():
    s = SanitizerAPISecurityScanner.__new__(SanitizerAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestAllowScript:
    def test_script_in_allowelements_fails(self):
        s = _scanner()
        body = "const sanitizer = new Sanitizer({allowElements: ['div', 'p', 'script']})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "sanitizer_allows_script_elements" in types


class TestAllowEventHandlers:
    def test_on_event_in_allowattributes_fails(self):
        s = _scanner()
        # _SAN_ALLOW_ON_RE: new Sanitizer({...allowAttributes...['onclick'] with quotes
        body = "const s = new Sanitizer({allowAttributes: {'onclick': ['*'], 'onload': ['img']}})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "sanitizer_allows_event_handlers" in types


class TestUntrustedInput:
    def test_sethtml_from_url_param_warns(self):
        s = _scanner()
        # _SAN_UNTRUSTED_INPUT_RE: .setHTML([^)]*searchParams
        body = "el.setHTML(searchParams.get('html'))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "sanitizer_untrusted_input" in types


class TestNotUsed:
    def test_no_sanitizer_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "sanitizer_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
