"""Tests for DocumentDomainSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.document_domain_security import DocumentDomainSecurityScanner


def _scanner():
    s = DocumentDomainSecurityScanner.__new__(DocumentDomainSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_document_domain_from_url_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.domain = searchParams.get('domain')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "document_domain_from_url_param" in types


def test_document_domain_relaxed():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.domain = 'example.com'"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "document_domain_relaxed" in types


def test_document_domain_set_then_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.domain = 'corp.example.com'\n"
        "const data = parent.document.cookie\n"
        "fetch('/steal', {body: data})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "document_domain_set_then_exfil" in types


def test_document_domain_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No domain manipulation</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "document_domain_not_used"
    assert results[0]["status"] == "PASS"


def test_document_domain_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "document_domain_not_used"
