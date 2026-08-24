"""Tests for JwtAdvancedSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.jwt_advanced_security import JwtAdvancedSecurityScanner


def _scanner():
    s = JwtAdvancedSecurityScanner.__new__(JwtAdvancedSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_jwt_none_algorithm():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const header = {alg: 'none', typ: 'JWT'}"
        "const jwt = btoa(JSON.stringify(header))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "jwt_none_algorithm" in types


def test_jwt_payload_logged():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const payload = JSON.parse(atob(token.split('.')[1]))"
        "console.log('JWT payload:', payload)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "jwt_payload_logged" in types


def test_jwt_weak_secret():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const token = jwt.sign(payload, 'secret', {expiresIn: '1h'})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "jwt_weak_secret" in types


def test_jwt_advanced_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No token authentication here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "jwt_advanced_not_used"
    assert results[0]["status"] == "PASS"


def test_jwt_advanced_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "jwt_advanced_not_used"
