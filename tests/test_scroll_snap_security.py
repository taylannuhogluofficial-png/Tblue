"""Tests for ScrollSnapSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.scroll_snap_security import ScrollSnapSecurityScanner


def _scanner():
    s = ScrollSnapSecurityScanner.__new__(ScrollSnapSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_scroll_position_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.style.scrollSnapType = 'y mandatory'\n"
        "document.addEventListener('scroll', () => {\n"
        "  const y = window.scrollY\n"
        "  sendBeacon('/scroll', JSON.stringify({position: y}))\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "scroll_position_exfiltrated" in types


def test_scroll_snap_injected_via_dom():
    s = _scanner()
    s.http.get.return_value = _resp(
        "sheet.insertRule('.container { scroll-snap-type: y mandatory }')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "scroll_snap_injected_via_dom" in types


def test_scroll_snap_into_sensitive_field():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.querySelector('#hidden-form').scrollIntoView({block: 'center'})\n"
        "// scrolls to password input and auth login form"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "scroll_snap_into_sensitive_field" in types


def test_scroll_snap_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No CSS snap or scrolling API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "scroll_snap_not_used"
    assert results[0]["status"] == "PASS"


def test_scroll_snap_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "scroll_snap_not_used"
