"""Tests for JavaScriptPrototypeChainScanner."""
from unittest.mock import MagicMock
from tblue.scanner.javascript_prototype_chain import JavaScriptPrototypeChainScanner


def _scanner():
    s = JavaScriptPrototypeChainScanner.__new__(JavaScriptPrototypeChainScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_proto_assign():
    s = _scanner()
    s.http.get.return_value = _resp("obj.__proto__ = JSON.parse(searchParams.get('data'))")
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "js_prototype_chain_proto_assign" in types


def test_object_prototype_modify():
    s = _scanner()
    s.http.get.return_value = _resp("Object.prototype.isAdmin = true")
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "js_prototype_chain_object_proto_modify" in types


def test_bracket_proto_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "obj.prototype[searchParams.get('key')] = searchParams.get('val')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "js_prototype_chain_bracket_from_param" in types


def test_getter_setter_gadget():
    s = _scanner()
    s.http.get.return_value = _resp(
        "Object.defineProperty(Object.prototype, 'polluted', {get: () => 'pwned'})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "js_prototype_chain_getter_setter_gadget" in types


def test_js_prototype_chain_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Regular page with no prototype</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "js_prototype_chain_not_used"
    assert results[0]["status"] == "PASS"
