"""Tests for LinkInjectionPassiveScanner."""
from unittest.mock import MagicMock
from tblue.scanner.link_injection_passive import LinkInjectionPassiveScanner


def _scanner():
    s = LinkInjectionPassiveScanner.__new__(LinkInjectionPassiveScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_href_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        '<a href="${searchParams.get(\'url\')}">Click here</a>'
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "link_injection_href_from_param" in types


def test_document_write_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.write('<a href=' + location.hash + '>link</a>')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "link_injection_document_write_from_param" in types


def test_window_location_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "window.location = searchParams.get('next')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "link_injection_window_location_from_param" in types


def test_link_injection_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Static content only</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "link_injection_not_used"
    assert results[0]["status"] == "PASS"


def test_link_injection_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "link_injection_not_used"
