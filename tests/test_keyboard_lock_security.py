"""Tests for KeyboardLockSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.keyboard_lock_security import KeyboardLockSecurityScanner


def _scanner():
    s = KeyboardLockSecurityScanner.__new__(KeyboardLockSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_keyboard_all_keys_locked():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.addEventListener('fullscreenchange', () => {\n"
        "  navigator.keyboard.lock([])\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "keyboard_all_keys_locked" in types


def test_keyboard_layout_fingerprinting():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.keyboard.getLayoutMap().then(map => {\n"
        "  const layout = Array.from(map.entries())\n"
        "  fetch('/fp', {body: JSON.stringify(layout)})\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "keyboard_layout_fingerprinting" in types


def test_keyboard_system_key_locked():
    s = _scanner()
    s.http.get.return_value = _resp(
        "navigator.keyboard.lock(['Escape', 'MetaLeft', 'F11'])"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "keyboard_system_key_locked" in types


def test_keyboard_lock_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No keyboard lock</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "keyboard_lock_not_used"
    assert results[0]["status"] == "PASS"


def test_keyboard_lock_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "keyboard_lock_not_used"
