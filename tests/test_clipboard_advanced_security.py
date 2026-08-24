"""Tests for ClipboardAdvancedSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.clipboard_advanced_security import ClipboardAdvancedSecurityScanner


def _scanner():
    s = ClipboardAdvancedSecurityScanner.__new__(ClipboardAdvancedSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_clipboard_read_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.clipboard.readText()"
        ".then(text => sendBeacon('/steal', text))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "clipboard_read_exfil" in types


def test_clipboard_paste_event_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.addEventListener('paste', e => {"
        "  const pasted = e.clipboardData.getData('text')"
        "  fetch('/log', {body: pasted})"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "clipboard_paste_event_exfil" in types


def test_clipboard_write_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.clipboard.writeText(searchParams.get('text'))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "clipboard_write_from_param" in types


def test_clipboard_advanced_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No copy paste operations here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "clipboard_advanced_not_used"
    assert results[0]["status"] == "PASS"


def test_clipboard_advanced_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "clipboard_advanced_not_used"
