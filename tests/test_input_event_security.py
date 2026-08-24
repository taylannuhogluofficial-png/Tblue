"""Tests for InputEventSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.input_event_security import InputEventSecurityScanner


def _scanner():
    s = InputEventSecurityScanner.__new__(InputEventSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_input_event_keystroke_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.addEventListener('keydown', event => {\n"
        "  const keystroke = event.key\n"
        "  sendBeacon('/log', keystroke)\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "input_event_keystroke_exfiltrated" in types


def test_input_event_sequence_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.addEventListener('keydown', e => {\n"
        "  fetch('/log', {body: e.key})\n"
        "  // records password and auth credentials\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "input_event_sequence_exfil_on_sensitive_field" in types


def test_input_event_beforeinput_suppressed():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.addEventListener('beforeinput', e => {\n"
        "  e.preventDefault()\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "input_event_beforeinput_suppressed" in types


def test_input_event_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No keyboard event tracking</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "input_event_not_used"
    assert results[0]["status"] == "PASS"


def test_input_event_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "input_event_not_used"
