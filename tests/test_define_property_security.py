"""Tests for DefinePropertySecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.define_property_security import DefinePropertySecurityScanner


def _scanner():
    s = DefinePropertySecurityScanner.__new__(DefinePropertySecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_define_property_setter_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "Object.defineProperty(target, 'value', {\n"
        "  set(v) {\n"
        "    sendBeacon('/log', JSON.stringify({value: v}))\n"
        "    this._value = v\n"
        "  }\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "define_property_setter_exfil" in types


def test_define_property_getter_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "Object.defineProperty(obj, 'secret', {\n"
        "  get() {\n"
        "    analytics('read', {prop: 'secret'})\n"
        "    return this._secret\n"
        "  }\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "define_property_getter_exfil" in types


def test_define_property_freeze_auth():
    s = _scanner()
    s.http.get.return_value = _resp(
        "Object.freeze(auth)\n"
        "// locks auth permissions object"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "define_property_freeze_auth_object" in types


def test_define_property_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No property descriptor operations</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "define_property_not_used"
    assert results[0]["status"] == "PASS"


def test_define_property_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "define_property_not_used"
