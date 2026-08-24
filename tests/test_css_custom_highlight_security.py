"""Tests for CSSCustomHighlightSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.css_custom_highlight_security import CSSCustomHighlightSecurityScanner


def _scanner():
    s = CSSCustomHighlightSecurityScanner.__new__(CSSCustomHighlightSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestRangeFromParam:
    def test_range_from_url_param_warns(self):
        s = _scanner()
        # _CCH_RANGE_FROM_PARAM_RE: new Highlight(...) ... searchParams/location.hash
        body = "const r = document.createRange()\nconst h = new Highlight(r)\nCSS.highlights.set('search', h)\nconst q = location.hash"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "css_highlight_range_from_url_param" in types


class TestSelectionTracking:
    def test_selection_tracking_warns(self):
        s = _scanner()
        # _CCH_SELECTION_TRACK_RE: getSelection ... new Highlight
        body = "const sel = window.getSelection()\nconst range = sel.getRangeAt(0)\nCSS.highlights.set('sel', new Highlight(range))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "css_highlight_selection_tracking" in types


class TestTextExfil:
    def test_text_exfiltrated_warns(self):
        s = _scanner()
        # _CCH_SELECTION_EXFIL_RE: CSS.highlights ... textContent ... sendBeacon
        body = "CSS.highlights.set('h', hl)\nconst txt = el.textContent\nsendBeacon('/track', txt)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "css_highlight_text_exfiltrated" in types


class TestNotUsed:
    def test_no_highlight_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "css_custom_highlight_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
