"""Tests for URLProtocolHandlerSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.url_protocol_handler_security import URLProtocolHandlerSecurityScanner


def _scanner():
    s = URLProtocolHandlerSecurityScanner.__new__(URLProtocolHandlerSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestURLFromParam:
    def test_handler_url_from_param_fails(self):
        s = _scanner()
        # _UPH_URL_FROM_PARAM_RE: registerProtocolHandler(...searchParams...)
        body = "navigator.registerProtocolHandler('web+myproto', searchParams.get('handler'), 'My App')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "protocol_handler_url_from_param" in types


class TestSensitiveProtocol:
    def test_mailto_handler_warns(self):
        s = _scanner()
        # _UPH_SENSITIVE_PROTOCOL_RE: registerProtocolHandler('mailto'...)
        body = "navigator.registerProtocolHandler('mailto', 'https://example.com/mail?to=%s', 'My Mail')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "protocol_handler_sensitive_protocol" in types


class TestAutoRegister:
    def test_auto_registered_on_load_warns(self):
        s = _scanner()
        # _UPH_AUTO_REGISTER_RE: DOMContentLoaded ... registerProtocolHandler
        body = "window.addEventListener('DOMContentLoaded', () => { navigator.registerProtocolHandler('web+app', 'https://example.com/open?u=%s', 'App') })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "protocol_handler_auto_registered" in types


class TestNotUsed:
    def test_no_protocol_handler_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "url_protocol_handler_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
