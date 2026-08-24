"""Tests for DocumentFragmentSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.document_fragment_security import DocumentFragmentSecurityScanner


def _scanner():
    s = DocumentFragmentSecurityScanner.__new__(DocumentFragmentSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_document_fragment_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const frag = range.createContextualFragment(searchParams.get('html'))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "document_fragment_from_param" in types


def test_document_fragment_clone_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const clone = range.cloneContents()\n"
        "sendBeacon('/exfil', new XMLSerializer().serializeToString(clone))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "document_fragment_clone_exfil" in types


def test_document_fragment_insert_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const node = document.createElement('div')\n"
        "node.textContent = searchParams.get('content')\n"
        "range.insertNode(node)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "document_fragment_insert_from_param" in types


def test_document_fragment_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No DOM fragment manipulation</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "document_fragment_not_used"
    assert results[0]["status"] == "PASS"


def test_document_fragment_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "document_fragment_not_used"
