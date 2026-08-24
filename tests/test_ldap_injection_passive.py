"""Tests for LDAPInjectionPassiveScanner."""
from unittest.mock import MagicMock
from tblue.scanner.ldap_injection_passive import LDAPInjectionPassiveScanner


def _scanner():
    s = LDAPInjectionPassiveScanner.__new__(LDAPInjectionPassiveScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_string_concat_filter():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const filter = '(uid=' + req.body.username + ')'; ldap.search(filter);"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "ldap_injection_string_concat_filter" in types


def test_error_disclosure():
    s = _scanner()
    s.http.get.return_value = _resp(
        "LDAPException: Invalid DN syntax: cn=admin,dc=example"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "ldap_injection_error_disclosure" in types


def test_dn_in_response():
    s = _scanner()
    s.http.get.return_value = _resp(
        "User: cn=johndoe,ou=employees,dc=example,dc=com authenticated"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "ldap_injection_dn_in_response" in types


def test_ldap_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Regular page</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "ldap_injection_not_used"
    assert results[0]["status"] == "PASS"


def test_ldap_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "ldap_injection_not_used"
