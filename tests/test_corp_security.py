"""Tests for CORPSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.corp_security import CORPSecurityScanner


def _scanner():
    s = CORPSecurityScanner.__new__(CORPSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_corp_cross_origin_policy():
    s = _scanner()
    s.http.get.return_value = _resp(
        "<html>resource</html>",
        headers={"Cross-Origin-Resource-Policy": "cross-origin"}
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "corp_cross_origin_policy" in types


def test_corp_no_cors_on_auth_resource():
    s = _scanner()
    s.http.get.return_value = _resp(
        "fetch('/api/token', {mode: 'no-cors', credentials: 'include'})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "corp_no_cors_on_auth_resource" in types


def test_corp_spectre_gadget():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const sab = new SharedArrayBuffer(1024)\n"
        "// cross-origin context usage\n"
        "Atomics.notify(new Int32Array(sab), 0, 1)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "corp_spectre_gadget" in types


def test_corp_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No resource policy</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "corp_not_used"
    assert results[0]["status"] == "PASS"


def test_corp_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "corp_not_used"
