"""Tests for LongAnimationFrameSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.long_animation_frame_security import LongAnimationFrameSecurityScanner


def _scanner():
    s = LongAnimationFrameSecurityScanner.__new__(LongAnimationFrameSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_long_animation_frame_data_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "observer.observe({type: 'long-animation-frame'})\n"
        "const durations = entries.map(e => e.duration)\n"
        "fetch('/track', {body: JSON.stringify(durations)})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "long_animation_frame_data_exfiltrated" in types


def test_long_animation_frame_keystroke_timing():
    s = _scanner()
    s.http.get.return_value = _resp(
        "observer.observe({type: 'long-animation-frame'})\n"
        "if (entry.duration > 50) {\n"
        "  passwordField.value = capturedKeydown\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "long_animation_frame_keystroke_timing" in types


def test_long_animation_frame_continuous_collection():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const obs = new PerformanceObserver(cb)\n"
        "obs.observe({type: 'long-animation-frame', buffered: true})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "long_animation_frame_continuous_collection" in types


def test_long_animation_frame_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No performance observer</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "long_animation_frame_not_used"
    assert results[0]["status"] == "PASS"


def test_long_animation_frame_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "long_animation_frame_not_used"
