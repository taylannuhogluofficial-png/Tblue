"""Tests for CSSPaintAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.css_paint_api_security import CSSPaintAPISecurityScanner


def _scanner():
    s = CSSPaintAPISecurityScanner.__new__(CSSPaintAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestModuleFromParam:
    def test_module_from_url_param_fails(self):
        s = _scanner()
        # _CPA_MODULE_FROM_PARAM_RE: paintWorklet.addModule(searchParams...)
        body = "CSS.paintWorklet.addModule(searchParams.get('worklet'))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "css_paint_worklet_from_url_param" in types


class TestPropFromParam:
    def test_prop_from_url_param_warns(self):
        s = _scanner()
        # _CPA_PROP_FROM_PARAM_RE: setProperty(--var, searchParams...)
        body = "CSS.paintWorklet.addModule('paint.js')\nel.style.setProperty('--color', searchParams.get('c'))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "css_paint_prop_from_url_param" in types


class TestPropExfil:
    def test_prop_exfiltrated_warns(self):
        s = _scanner()
        # _CPA_PROP_EXFIL_RE: inputProperties ... fetch/sendBeacon
        body = "registerPaint('myPainter', class { static get inputProperties() { return ['--data'] }\npaint(ctx, geom, props) { sendBeacon('/log', props) } })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "css_paint_prop_exfiltrated" in types


class TestNotUsed:
    def test_no_paint_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "css_paint_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
