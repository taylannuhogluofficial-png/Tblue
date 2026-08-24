"""Tests for PermissionPolicySecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.permission_policy_security import PermissionPolicySecurityScanner


def _scanner():
    s = PermissionPolicySecurityScanner.__new__(PermissionPolicySecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_permission_policy_wildcard_sensitive():
    s = _scanner()
    s.http.get.return_value = _resp(
        "<meta>",
        headers={"Permissions-Policy": "camera=*, microphone=*, geolocation=*"}
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "permission_policy_wildcard_sensitive" in types


def test_permission_policy_iframe_over_permissive():
    s = _scanner()
    s.http.get.return_value = _resp(
        "<iframe src='https://widget.example.com' allow='camera; microphone; geolocation'></iframe>"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "permission_policy_iframe_over_permissive" in types


def test_permission_policy_dangerous_feature_wildcard():
    s = _scanner()
    s.http.get.return_value = _resp(
        "<meta>",
        headers={"Permissions-Policy": "serial=*, usb=*"}
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "permission_policy_dangerous_feature_wildcard" in types


def test_permission_policy_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No policy here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "permission_policy_not_used"
    assert results[0]["status"] == "PASS"


def test_permission_policy_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "permission_policy_not_used"
