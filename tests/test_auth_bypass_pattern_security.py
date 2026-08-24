"""Tests for AuthBypassPatternSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.auth_bypass_pattern_security import AuthBypassPatternSecurityScanner


def _scanner():
    s = AuthBypassPatternSecurityScanner.__new__(AuthBypassPatternSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_auth_bypass_role_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const isAdmin = searchParams.get('isAdmin') === 'true'"
        "if (isAdmin) { grantAccess() }"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "auth_bypass_role_from_param" in types


def test_auth_bypass_client_side_only():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const isAuthenticated = localStorage.getItem('isAuthenticated') === 'true'"
        "if (isAuthenticated) { showDashboard() }"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "auth_bypass_client_side_only" in types


def test_auth_bypass_boolean_short_circuit():
    s = _scanner()
    s.http.get.return_value = _resp(
        "if (isAdmin || true) { deleteUser(id) }"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "auth_bypass_boolean_short_circuit" in types


def test_auth_bypass_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No authentication or access control here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "auth_bypass_not_used"
    assert results[0]["status"] == "PASS"


def test_auth_bypass_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "auth_bypass_not_used"
