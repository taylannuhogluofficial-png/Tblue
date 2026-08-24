"""Tests for ImportMapSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.import_map_security import ImportMapSecurityScanner


def _scanner():
    s = ImportMapSecurityScanner.__new__(ImportMapSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestExternalURL:
    def test_external_specifier_warns(self):
        s = _scanner()
        body = '<script type="importmap">{"imports": {"mylib": "https://evil.example.com/lib.js"}}</script>'
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "import_map_external_url" in types


class TestDynamicInjection:
    def test_importmap_via_innerhtml_fails(self):
        s = _scanner()
        # _IM_DYNAMIC_RE: innerHTML ... importmap within 200 non-semicolon chars
        body = "el.innerHTML = '<script type=\"importmap\">' + userInput + '</script>'"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "import_map_injected_dynamically" in types


class TestMissingIntegrity:
    def test_no_integrity_warns(self):
        s = _scanner()
        body = '<script type="importmap">{"imports": {"app": "./app.js"}}</script>'
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "import_map_missing_integrity" in types

    def test_with_integrity_passes(self):
        s = _scanner()
        body = '<script type="importmap" integrity="sha384-abc123">{"imports": {}}</script>'
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "import_map_missing_integrity" not in types


class TestNotUsed:
    def test_no_import_map_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "import_map_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
