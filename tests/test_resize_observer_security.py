"""Tests for ResizeObserverSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.resize_observer_security import ResizeObserverSecurityScanner


def _scanner():
    s = ResizeObserverSecurityScanner.__new__(ResizeObserverSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_resize_observer_content_rect_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const ro = new ResizeObserver(entries => {"
        "  const rect = entries[0].contentRect"
        "  sendBeacon('/layout', JSON.stringify({w: rect.width, h: rect.height}))"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "resize_observer_content_rect_exfil" in types


def test_resize_observer_box_size_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const ro = new ResizeObserver(entries => {"
        "  const box = entries[0].borderBoxSize"
        "  analytics('element_size', {box: box})"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "resize_observer_box_size_exfil" in types


def test_resize_observer_sensitive_target():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const resizeObserver = new ResizeObserver(cb)"
        "resizeObserver.observe(passwordField.token)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "resize_observer_sensitive_target" in types


def test_resize_observer_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No element sizing observation here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "resize_observer_not_used"
    assert results[0]["status"] == "PASS"


def test_resize_observer_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "resize_observer_not_used"
