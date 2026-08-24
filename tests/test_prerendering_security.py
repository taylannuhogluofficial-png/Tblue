"""Tests for PrerenderingSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.prerendering_security import PrerenderingSecurityScanner


def _scanner():
    s = PrerenderingSecurityScanner.__new__(PrerenderingSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_prerendering_sensitive_operation():
    s = _scanner()
    s.http.get.return_value = _resp(
        "if (document.prerendering) {\n"
        "  fetch('/api/track', {body: userId})\n"
        "  localStorage.setItem('prerendered', true)\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "prerendering_sensitive_operation" in types


def test_prerendering_url_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "<link rel='prerender' href='speculationrules'>\n"
        "<script type='speculationrules'>\n"
        "const target = searchParams.get('target')\n"
        "</script>"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "prerendering_url_from_param" in types


def test_prerendering_state_change_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.addEventListener('prerenderingchange', () => {\n"
        "  sendBeacon('/activate', JSON.stringify({ts: Date.now()}))\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "prerendering_state_change_exfiltrated" in types


def test_prerendering_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No prerendering</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "prerendering_not_used"
    assert results[0]["status"] == "PASS"


def test_prerendering_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "prerendering_not_used"
