"""Tests for ImportAssertionsSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.import_assertions_security import ImportAssertionsSecurityScanner


def _scanner():
    s = ImportAssertionsSecurityScanner.__new__(ImportAssertionsSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_importmap_injected_via_dom():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.head.innerHTML += '<script type=\"importmap\">{\"imports\":{\"lib\":\"/evil.js\"}}</script>'"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "importmap_injected_via_dom" in types


def test_importmap_external_specifier():
    s = _scanner()
    s.http.get.return_value = _resp(
        '<script type="importmap">{"imports":{"lib":"https://cdn.evil.com/lib.js"}}</script>'
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "importmap_external_specifier" in types


def test_import_json_module_sensitive_path():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const data = await import('/api/token.json') assert {type: 'json'}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "import_json_module_sensitive_path" in types


def test_import_assertions_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No module imports</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "import_assertions_not_used"
    assert results[0]["status"] == "PASS"


def test_import_assertions_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "import_assertions_not_used"
