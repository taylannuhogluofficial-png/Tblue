"""Tests for DocumentPIPSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.document_pip_security import DocumentPIPSecurityScanner


def _scanner():
    s = DocumentPIPSecurityScanner.__new__(DocumentPIPSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestAutoOpen:
    def test_auto_open_on_load_fails(self):
        s = _scanner()
        body = "window.addEventListener('load', async () => { const pipWindow = await documentPictureInPicture.requestWindow() })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "document_pip_auto_open" in types


class TestSensitiveContent:
    def test_password_in_pip_fails(self):
        s = _scanner()
        # _DPIP_SENSITIVE_RE: documentPictureInPicture ... password within 400 non-semicolon chars
        body = "const pip = await documentPictureInPicture.requestWindow()\npip.document.body.innerHTML = passwordField.outerHTML"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "document_pip_sensitive_content" in types


class TestDataTransmitted:
    def test_pip_data_sent_warns(self):
        s = _scanner()
        # _DPIP_SEND_RE: pipWindow ... fetch within 300 non-semicolon chars
        body = "const pipWindow = await documentPictureInPicture.requestWindow()\nfetch('/log', {body: pipWindow.document.title})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "document_pip_data_transmitted" in types


class TestNotUsed:
    def test_no_pip_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "document_pip_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
