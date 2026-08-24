"""Tests for PictureInPictureSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.picture_in_picture_security import PictureInPictureSecurityScanner


def _scanner():
    s = PictureInPictureSecurityScanner.__new__(PictureInPictureSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_pip_auto_enter_on_load():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.addEventListener('DOMContentLoaded', () => {\n"
        "  video.requestPictureInPicture()\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "pip_auto_enter_on_load" in types


def test_pip_state_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "video.addEventListener('enterpictureinpicture', e => {\n"
        "  const pipWindow = e.pictureInPictureWindow\n"
        "  fetch('/log', {body: 'pip_entered'})\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "pip_state_exfiltrated" in types


def test_pip_window_size_fingerprinting():
    s = _scanner()
    s.http.get.return_value = _resp(
        "video.addEventListener('enterpictureinpicture', e => {\n"
        "  const PictureInPictureWindow = e.pictureInPictureWindow\n"
        "  const dims = {w: PictureInPictureWindow.width, h: PictureInPictureWindow.height}\n"
        "  sendBeacon('/fp', JSON.stringify(dims))\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "pip_window_size_fingerprinting" in types


def test_pip_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No PiP here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "pip_not_used"
    assert results[0]["status"] == "PASS"


def test_pip_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "pip_not_used"
