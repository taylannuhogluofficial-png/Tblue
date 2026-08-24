"""Tests for TextFragmentSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.text_fragment_security import TextFragmentSecurityScanner


def _scanner():
    s = TextFragmentSecurityScanner.__new__(TextFragmentSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestLinkInjection:
    def test_link_injection_fails(self):
        s = _scanner()
        body = "const fragment = searchParams.get('q')\nlocation.href = '#:~:text=' + fragment"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "text_fragment_link_injection" in types


class TestScrollOracle:
    def test_scroll_oracle_fails(self):
        s = _scanner()
        body = "const dir = document.fragmentDirective\nconst obs = new IntersectionObserver(e => sendBeacon('/log', e[0].isIntersecting))\nobs.observe(document.body)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "text_fragment_scroll_oracle" in types


class TestHighlightExfil:
    def test_highlight_exfil_fails(self):
        s = _scanner()
        body = "const fd = document.fragmentDirective\nconst text = document.querySelector('.highlight').textContent\nfetch('/exfil', {body: text})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "text_fragment_highlight_exfil" in types


class TestNotUsed:
    def test_no_text_fragment_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "text_fragment_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
