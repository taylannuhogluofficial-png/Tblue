"""Tests for MassAssignmentSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.mass_assignment_security import MassAssignmentSecurityScanner


def _scanner():
    s = MassAssignmentSecurityScanner.__new__(MassAssignmentSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_spread_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const user = {...JSON.parse(searchParams.get('data'))}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "mass_assignment_spread_from_param" in types


def test_object_assign_model():
    s = _scanner()
    s.http.get.return_value = _resp(
        "Object.assign(this, JSON.parse(searchParams.get('update')))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "mass_assignment_object_assign_model" in types


def test_role_escalation():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const role = JSON.parse(searchParams.get('userRole'))"
        "Object.assign(user, {role: role})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "mass_assignment_role_escalation" in types


def test_mass_assignment_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No object assignment here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "mass_assignment_not_used"
    assert results[0]["status"] == "PASS"


def test_mass_assignment_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "mass_assignment_not_used"
