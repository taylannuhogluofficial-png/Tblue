"""Tests for ErrorEventSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.error_event_security import ErrorEventSecurityScanner


def _scanner():
    s = ErrorEventSecurityScanner.__new__(ErrorEventSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_error_event_stack_trace_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "try {\n"
        "  riskyOp()\n"
        "} catch(error) {\n"
        "  const stack = error.stack\n"
        "  sendBeacon('/log', stack)\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "error_event_stack_trace_exfil" in types


def test_error_event_window_onerror_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "window.onerror = (msg, src, line, col, err) => {\n"
        "  fetch('/errors', {body: JSON.stringify({msg, src, line})})\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "error_event_window_onerror_exfil" in types


def test_error_event_sensitive_in_message():
    s = _scanner()
    s.http.get.return_value = _resp(
        "throw new Error('Invalid token: ' + authToken)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "error_event_sensitive_in_message" in types


def test_error_event_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No exception handling</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "error_event_not_used"
    assert results[0]["status"] == "PASS"


def test_error_event_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "error_event_not_used"
