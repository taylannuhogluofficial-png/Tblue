"""Tests for LDAPInjectionSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.ldap_injection_security import LDAPInjectionSecurityScanner


def _scanner():
    s = LDAPInjectionSecurityScanner.__new__(LDAPInjectionSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_ldap_injection_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "ldap.search('cn=' + searchParams.get('user') + ',dc=example,dc=com')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "ldap_injection_from_param" in types


def test_ldap_injection_string_concat():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const filter = '(cn=' + username + ')'"
        "ldapFilter = filter"
        "ldap.search(filter)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "ldap_injection_string_concat" in types


def test_ldap_wildcard_injection_pattern():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const ldapFilter = '(&(cn=*)(objectClass=user))'"
        "ldap.search(ldapFilter)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "ldap_wildcard_injection_pattern" in types


def test_ldap_injection_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No directory service code here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "ldap_injection_not_used"
    assert results[0]["status"] == "PASS"


def test_ldap_injection_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "ldap_injection_not_used"
