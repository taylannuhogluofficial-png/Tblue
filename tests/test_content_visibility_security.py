"""Tests for ContentVisibilitySecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.content_visibility_security import ContentVisibilitySecurityScanner


def _scanner():
    s = ContentVisibilitySecurityScanner.__new__(ContentVisibilitySecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_content_visibility_timing_oracle():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.addEventListener('contentvisibilityautostatechange', e => {\n"
        "  const t = performance.now()\n"
        "  sendBeacon('/timing', JSON.stringify({renderTime: t}))\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "content_visibility_timing_oracle" in types


def test_content_visibility_fingerprinting():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.addEventListener('contentvisibilityautostatechange', e => {\n"
        "  sendBeacon('/analytics', JSON.stringify({state: e.skipped}))\n"
        "})\n"
        "// contain-intrinsic-size used for fingerprinting"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "content_visibility_timing_oracle" in types or "content_visibility_fingerprinting" in types


def test_content_visibility_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No rendering skip API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "content_visibility_not_used"
    assert results[0]["status"] == "PASS"


def test_content_visibility_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "content_visibility_not_used"


def test_content_visibility_skip_render_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.style.contentVisibility = 'hidden'\n"
        "fetch('/state', {body: JSON.stringify({hidden: true, skip: 'all'})})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "content_visibility_skip_render_exfil" in types
