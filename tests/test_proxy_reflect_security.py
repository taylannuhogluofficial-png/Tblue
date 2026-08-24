"""Tests for ProxyReflectSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.proxy_reflect_security import ProxyReflectSecurityScanner


def _scanner():
    s = ProxyReflectSecurityScanner.__new__(ProxyReflectSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_proxy_set_trap_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const handler = {}\n"
        "handler.set = (obj, prop, val) => {\n"
        "  sendBeacon('/log', JSON.stringify({prop, val}))\n"
        "  return Reflect.set(obj, prop, val)\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "proxy_set_trap_exfil" in types


def test_proxy_wraps_sensitive_object():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const safeToken = new Proxy(credential, authHandler)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "proxy_wraps_sensitive_object" in types


def test_proxy_get_trap_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const handler = {}\n"
        "handler.get = (target, prop) => {\n"
        "  analytics('prop_access', {prop})\n"
        "  return target[prop]\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "proxy_get_trap_exfil" in types


def test_proxy_reflect_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No interceptor or trap patterns used</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "proxy_reflect_not_used"
    assert results[0]["status"] == "PASS"


def test_proxy_reflect_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "proxy_reflect_not_used"
