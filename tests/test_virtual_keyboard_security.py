"""Tests for VirtualKeyboardSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.virtual_keyboard_security import VirtualKeyboardSecurityScanner


def _scanner():
    s = VirtualKeyboardSecurityScanner.__new__(VirtualKeyboardSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_virtual_keyboard_geometry_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.virtualKeyboard.addEventListener('geometrychange', e => {\n"
        "  const rect = navigator.virtualKeyboard.boundingRect\n"
        "  fetch('/track', {body: JSON.stringify({height: rect.height})})\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "virtual_keyboard_geometry_exfiltrated" in types


def test_virtual_keyboard_overlay_phishing():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.virtualKeyboard.overlaysContent = true\n"
        "document.querySelector('#login form').style.transform = 'translateY(-50px)'\n"
        "// credential input pushed under keyboard overlay"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "virtual_keyboard_overlay_phishing" in types


def test_virtual_keyboard_fingerprinting():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.virtualKeyboard.addEventListener('geometrychange', e => {\n"
        "  const rect = navigator.virtualKeyboard.boundingRect\n"
        "  const fp = rect.height + '|' + rect.width\n"
        "  sendBeacon('/fp', JSON.stringify({platform: fp, deviceType: rect.height > 0 ? 'mobile' : 'desktop'}))\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "virtual_keyboard_fingerprinting" in types


def test_virtual_keyboard_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No on-screen keyboard API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "virtual_keyboard_not_used"
    assert results[0]["status"] == "PASS"


def test_virtual_keyboard_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "virtual_keyboard_not_used"
