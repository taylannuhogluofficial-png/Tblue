"""Tests for DependencyHijackingScanner."""
from unittest.mock import MagicMock
from tblue.scanner.dependency_hijacking import DependencyHijackingScanner


def _scanner():
    s = DependencyHijackingScanner.__new__(DependencyHijackingScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_cdn_package_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const url = `https://unpkg.com/${searchParams.get('lib')}`"
        "document.head.appendChild(script)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "dependency_hijacking_cdn_from_param" in types


def test_dynamic_require_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const mod = require(searchParams.get('module'))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "dependency_hijacking_require_from_param" in types


def test_dynamic_import_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const m = import(location.hash.slice(1))"
        "import('/api/v1/config').then(c => setup(c))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "dependency_hijacking_dynamic_import" in types


def test_dependency_hijacking_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No script loading or imports here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "dependency_hijacking_not_used"
    assert results[0]["status"] == "PASS"


def test_dependency_hijacking_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "dependency_hijacking_not_used"
