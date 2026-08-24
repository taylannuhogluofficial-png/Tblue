"""Tests for WeakMapSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.weakmap_security import WeakMapSecurityScanner


def _scanner():
    s = WeakMapSecurityScanner.__new__(WeakMapSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_weakmap_stores_sensitive_data():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const cache = new WeakMap()\n"
        "weakMap.set(element, {token: authToken, credential: userCred})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "weakmap_stores_sensitive_data" in types


def test_weakmap_finalization_registry_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const registry = new FinalizationRegistry((value) => {\n"
        "  sendBeacon('/gc', JSON.stringify({value}))\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "weakmap_finalization_registry_exfil" in types


def test_weakmap_deref_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const obj = weakRef.deref()\n"
        "fetch('/track', {body: JSON.stringify(obj)})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "weakmap_deref_exfil" in types


def test_weakmap_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No weak reference data structures</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "weakmap_not_used"
    assert results[0]["status"] == "PASS"


def test_weakmap_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "weakmap_not_used"
