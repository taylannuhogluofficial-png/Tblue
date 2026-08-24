"""Tests for FullscreenSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.fullscreen_security import FullscreenSecurityScanner


def _scanner():
    s = FullscreenSecurityScanner.__new__(FullscreenSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_fullscreen_auto_triggered():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.documentElement.requestFullscreen()\n"
        "// invoked on DOMContentLoaded immediately"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "fullscreen_auto_triggered" in types


def test_fullscreen_phishing_overlay():
    s = _scanner()
    s.http.get.return_value = _resp(
        "loginModal.requestFullscreen()\n"
        ".then(() => {\n"
        "  showFakeCredentialForm()\n"
        "  // auth form displayed fullscreen\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "fullscreen_phishing_overlay" in types


def test_fullscreen_exfil_on_enter():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.addEventListener('fullscreenchange', () => {\n"
        "  if (document.fullscreenElement) {\n"
        "    sendBeacon('/track', JSON.stringify({entered: true}))\n"
        "  }\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "fullscreen_exfil_on_enter" in types


def test_fullscreen_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No browser fullscreen API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "fullscreen_not_used"
    assert results[0]["status"] == "PASS"


def test_fullscreen_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "fullscreen_not_used"
