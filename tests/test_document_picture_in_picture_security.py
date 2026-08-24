"""Tests for DocumentPictureInPictureSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.document_picture_in_picture_security import DocumentPictureInPictureSecurityScanner


def _scanner():
    s = DocumentPictureInPictureSecurityScanner.__new__(DocumentPictureInPictureSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_document_pip_auto_opened():
    s = _scanner()
    s.http.get.return_value = _resp(
        "window.documentPictureInPicture.requestWindow({width: 300})\n"
        "// called on DOMContentLoaded immediately at page load"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "document_pip_auto_opened" in types


def test_document_pip_phishing_overlay():
    s = _scanner()
    s.http.get.return_value = _resp(
        "documentPictureInPicture.requestWindow({width: 400, height: 300})\n"
        ".then(pipWin => {\n"
        "  pipWin.document.body.innerHTML = loginForm\n"
        "  // credential input shown in floating PiP\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "document_pip_phishing_overlay" in types


def test_document_pip_content_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const w = documentPictureInPicture.requestWindow({width: searchParams.get('w')})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "document_pip_content_from_param" in types


def test_document_pip_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No floating window API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "document_pip_not_used"
    assert results[0]["status"] == "PASS"


def test_document_pip_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "document_pip_not_used"
