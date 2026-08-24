"""Tests for FontLoadingSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.font_loading_security import FontLoadingSecurityScanner


def _scanner():
    s = FontLoadingSecurityScanner.__new__(FontLoadingSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestTimingOracle:
    def test_font_timing_oracle_warns(self):
        s = _scanner()
        # _FONT_TIMING_RE: document.fonts.check(...) ... performance.now
        body = "const loaded = document.fonts.check('12px Arial')\nconst t = performance.now()"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "font_timing_oracle" in types


class TestDataExfil:
    def test_font_data_exfiltrated_warns(self):
        s = _scanner()
        # _FONT_EXFIL_RE: document.fonts ... fetch/sendBeacon ... font/family
        body = "document.fonts.ready.then(() => sendBeacon('/track', JSON.stringify({font: 'Arial'})))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "font_data_exfiltrated" in types


class TestCSSFontSSRF:
    def test_css_font_ssrf_warns(self):
        s = _scanner()
        # _FONT_CSS_SSRF_RE: @font-face ... src: url('https://...
        body = "@font-face { font-family: 'Custom'; src: url('https://evil.com/font.woff2') }"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "font_css_ssrf_probe" in types


class TestNotUsed:
    def test_no_font_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "font_loading_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
