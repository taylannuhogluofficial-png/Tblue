"""Tests for DocumentPIPApiSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.document_pip_api_security import DocumentPIPApiSecurityScanner


def _scanner():
    s = DocumentPIPApiSecurityScanner.__new__(DocumentPIPApiSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestSensitiveContent:
    def test_sensitive_content_in_pip_warns(self):
        s = _scanner()
        # _PIP_SENSITIVE_CONTENT_RE: documentPictureInPicture ... token
        body = "documentPictureInPicture.requestWindow({width: 320, height: 240})\nconst tok = token"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "pip_sensitive_content_exposed" in types


class TestParentDOM:
    def test_pip_accesses_parent_dom_fails(self):
        s = _scanner()
        # _PIP_PARENT_DOM_RE: pipWindow ... opener. ... document
        body = "const pip = pipWindow\nconst doc = pip.opener.document"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "pip_accesses_parent_dom" in types


class TestAutoOpen:
    def test_pip_auto_opens_on_load_warns(self):
        s = _scanner()
        # _PIP_AUTO_OPEN_RE: DOMContentLoaded ... requestWindow
        body = "window.addEventListener('DOMContentLoaded', () => documentPictureInPicture.requestWindow({width: 200, height: 150}))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "pip_auto_opened_on_load" in types


class TestNotUsed:
    def test_no_pip_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "document_pip_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
