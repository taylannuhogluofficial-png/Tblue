"""Tests for SAMLSecurityPassiveScanner."""
from unittest.mock import MagicMock
from tblue.scanner.saml_security_passive import SAMLSecurityPassiveScanner


def _scanner():
    s = SAMLSecurityPassiveScanner.__new__(SAMLSecurityPassiveScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_saml_weak_signature():
    s = _scanner()
    s.http.get.return_value = _resp(
        '<SAMLResponse><samlp:Response><saml:Assertion>'
        '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha1"/>'
        '</saml:Assertion></samlp:Response></SAMLResponse>'
    )
    results = s.scan("http://example.com/saml/acs")
    types = [r["type"] for r in results]
    assert "saml_weak_signature_algorithm" in types


def test_saml_error_disclosure():
    s = _scanner()
    s.http.get.return_value = _resp(
        "SAMLException: Invalid SAML response signature at org.opensaml.saml.common"
    )
    results = s.scan("http://example.com/saml/acs")
    types = [r["type"] for r in results]
    assert "saml_error_disclosure" in types


def test_saml_nameid_unspecified():
    s = _scanner()
    s.http.get.return_value = _resp(
        '<SAMLResponse><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">'
        'user@example.com</saml:NameID></SAMLResponse>'
    )
    results = s.scan("http://example.com/saml/acs")
    types = [r["type"] for r in results]
    assert "saml_nameid_format_unspecified" in types


def test_saml_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Regular HTML page</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "saml_security_not_used"
    assert results[0]["status"] == "PASS"


def test_saml_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "saml_security_not_used"
