"""Tests for WebShareSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.web_share_security import WebShareSecurityScanner


def _scanner():
    s = WebShareSecurityScanner.__new__(WebShareSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_web_share_credentials():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.share({title: 'My key', text: 'apiKey: ' + apiKey, url: location.href})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "web_share_credentials" in types


def test_web_share_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.share({title: 'Share', text: searchParams.get('content')})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "web_share_from_param" in types


def test_web_share_files():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.share({files: [new File([data], 'doc.pdf')], title: 'Document'})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "web_share_files" in types


def test_web_share_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No sharing functionality here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "web_share_not_used"
    assert results[0]["status"] == "PASS"


def test_web_share_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "web_share_not_used"
