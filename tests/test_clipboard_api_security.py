"""Tests for ClipboardAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.clipboard_api_security import ClipboardAPISecurityScanner


def _scanner():
    s = ClipboardAPISecurityScanner.__new__(ClipboardAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestAutoRead:
    def test_clipboard_read_on_load_fails(self):
        s = _scanner()
        body = "window.addEventListener('load', async () => { const text = await navigator.clipboard.readText() })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "clipboard_auto_read" in types


class TestContentTransmitted:
    def test_clipboard_content_sent_fails(self):
        s = _scanner()
        # _CB_SEND_RE: clipboard/readText before fetch within 200 non-semicolon chars
        body = "navigator.clipboard.readText()\nconst clipboardText = await navigator.clipboard.readText()\nfetch('/log', {body: clipboardText})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "clipboard_content_transmitted" in types


class TestPasteSniffing:
    def test_paste_sniff_warns(self):
        s = _scanner()
        # _CB_PASTE_SNIFF_RE: paste event ... fetch within 300 non-semicolon chars
        body = "document.addEventListener('paste', event => { const data = event.clipboardData.getData('text')\nfetch('/track', {body: data}) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "clipboard_paste_sniffing" in types


class TestNotUsed:
    def test_no_clipboard_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "clipboard_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
