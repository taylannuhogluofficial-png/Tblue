"""Tests for DynamicImportSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.dynamic_import_security import DynamicImportSecurityScanner


def _scanner():
    s = DynamicImportSecurityScanner.__new__(DynamicImportSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestURLFromParam:
    def test_import_from_url_param_fails(self):
        s = _scanner()
        body = "import(searchParams.get('module')).then(m => m.init())"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "dynamic_import_url_from_param" in types


class TestConcatenatedURL:
    def test_concatenated_import_url_warns(self):
        s = _scanner()
        body = "import('./plugins/' + pluginName + '.js').then(p => p.run())"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "dynamic_import_concatenated_url" in types


class TestMetaExfil:
    def test_import_meta_exfiltrated_warns(self):
        s = _scanner()
        body = "const url = import.meta.url\nfetch('/track', {body: url})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "dynamic_import_meta_exfil" in types


class TestNotUsed:
    def test_no_dynamic_import_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "dynamic_import_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
