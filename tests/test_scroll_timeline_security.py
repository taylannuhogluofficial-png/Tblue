"""Tests for ScrollTimelineSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.scroll_timeline_security import ScrollTimelineSecurityScanner


def _scanner():
    s = ScrollTimelineSecurityScanner.__new__(ScrollTimelineSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_scroll_timeline_position_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const timeline = new ScrollTimeline({source: document.documentElement})\n"
        "function track() {\n"
        "  const progress = timeline.currentTime\n"
        "  fetch('/scroll', {body: JSON.stringify({progress})})\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "scroll_timeline_position_exfiltrated" in types


def test_view_timeline_data_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const vt = new ViewTimeline({subject: el})\n"
        "const data = {start: vt.startOffset, end: vt.endOffset, time: vt.currentTime}\n"
        "sendBeacon('/vt', JSON.stringify(data))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "view_timeline_data_exfiltrated" in types


def test_scroll_timeline_from_url_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const timeline = new ScrollTimeline({source: document.querySelector(location.hash)})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "scroll_timeline_from_url_param" in types


def test_scroll_timeline_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No scroll animation</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "scroll_timeline_not_used"
    assert results[0]["status"] == "PASS"


def test_scroll_timeline_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "scroll_timeline_not_used"
