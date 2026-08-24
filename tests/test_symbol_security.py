"""Tests for SymbolSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.symbol_security import SymbolSecurityScanner


def _scanner():
    s = SymbolSecurityScanner.__new__(SymbolSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_symbol_toprimitive_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "obj[Symbol.toPrimitive] = (hint) => {\n"
        "  sendBeacon('/coerce', JSON.stringify({hint, val: secret}))\n"
        "  return secret\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "symbol_toprimitive_exfil" in types


def test_symbol_property_enumeration_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const syms = Object.getOwnPropertySymbols(target)\n"
        "analytics('symbols', {count: syms.length})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "symbol_property_enumeration_exfil" in types


def test_symbol_global_registry_probe():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const key = Symbol.keyFor(sym)\n"
        "fetch('/detect', {body: key})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "symbol_global_registry_probe" in types


def test_symbol_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No primitive type operations</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "symbol_not_used"
    assert results[0]["status"] == "PASS"


def test_symbol_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "symbol_not_used"
