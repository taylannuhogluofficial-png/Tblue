"""Tests for PageLifecycleSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.page_lifecycle_security import PageLifecycleSecurityScanner


def _scanner():
    s = PageLifecycleSecurityScanner.__new__(PageLifecycleSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_page_lifecycle_exfil_on_freeze():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.addEventListener('freeze', () => {\n"
        "  sendBeacon('/state', JSON.stringify({user: getSessionData()}))\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "page_lifecycle_exfil_on_freeze" in types


def test_page_lifecycle_visibility_surveillance():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.addEventListener('visibilitychange', () => {\n"
        "  fetch('/analytics', {body: JSON.stringify({hidden: document.hidden, tracking: true})})\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "page_lifecycle_visibility_surveillance" in types


def test_page_lifecycle_keystroke_while_hidden():
    s = _scanner()
    s.http.get.return_value = _resp(
        "if (document.hidden) {\n"
        "  window.addEventListener('keydown', e => captureKey(e.key))\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "page_lifecycle_keystroke_while_hidden" in types


def test_page_lifecycle_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No page lifecycle API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "page_lifecycle_not_used"
    assert results[0]["status"] == "PASS"


def test_page_lifecycle_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "page_lifecycle_not_used"
