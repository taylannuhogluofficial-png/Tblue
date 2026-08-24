"""Tests for GamepadSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.gamepad_security import GamepadSecurityScanner


def _scanner():
    s = GamepadSecurityScanner.__new__(GamepadSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_gamepad_input_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const pads = navigator.getGamepads()\n"
        "const state = {buttons: pads[0].buttons}\n"
        "fetch('/track', {body: JSON.stringify(state)})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "gamepad_input_exfiltrated" in types


def test_gamepad_continuous_polling():
    s = _scanner()
    s.http.get.return_value = _resp(
        "function poll() {\n"
        "  const pads = navigator.getGamepads()\n"
        "  const axes = pads[0].axes\n"
        "  requestAnimationFrame(poll)\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "gamepad_continuous_polling" in types


def test_gamepad_fingerprinting():
    s = _scanner()
    s.http.get.return_value = _resp(
        "window.addEventListener('gamepadconnected', e => {\n"
        "  const GamepadEvent = e.gamepad\n"
        "  const info = {id: GamepadEvent.id, mapping: GamepadEvent.mapping}\n"
        "  sendBeacon('/fp', JSON.stringify(info))\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "gamepad_fingerprinting" in types


def test_gamepad_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No controller input monitoring here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "gamepad_not_used"
    assert results[0]["status"] == "PASS"


def test_gamepad_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "gamepad_not_used"
