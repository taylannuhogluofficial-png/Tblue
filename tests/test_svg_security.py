"""Tests for SVGSecurityScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.svg_security import SVGSecurityScanner

URL = "https://example.com"


def _svg_resp(body, status=200, content_type="image/svg+xml", cd=""):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {
        "content-type": content_type,
        "content-disposition": cd,
    }
    return r


class TestSVGSecurity(unittest.TestCase):
    def _make(self):
        s = SVGSecurityScanner.__new__(SVGSecurityScanner)
        s.http = MagicMock()
        return s

    # ── No SVG files ──────────────────────────────────────────────────────────

    def test_no_svg_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = _svg_resp("", status=404, content_type="text/html")
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── SVG with embedded <script> ────────────────────────────────────────────

    def test_svg_with_script_fails(self):
        svg = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if u.endswith(".svg"):
                    return _svg_resp(svg)
                return _svg_resp("", status=404, content_type="text/html")
            m.get.side_effect = side_effect
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("script" in r["type"].lower() for r in fails))

    # ── SVG with onload event handler ─────────────────────────────────────────

    def test_svg_with_onload_fails(self):
        svg = '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>'
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if u.endswith(".svg"):
                    return _svg_resp(svg)
                return _svg_resp("", status=404, content_type="text/html")
            m.get.side_effect = side_effect
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("event" in r["type"].lower() or "handler" in r["type"].lower() or "onload" in r["type"].lower() for r in fails))

    # ── SVG with foreignObject ────────────────────────────────────────────────

    def test_svg_with_foreign_object_warns(self):
        svg = '<svg><foreignObject width="100" height="100"><body xmlns="http://www.w3.org/1999/xhtml"><div>Hello</div></body></foreignObject></svg>'
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if u.endswith(".svg"):
                    return _svg_resp(svg)
                return _svg_resp("", status=404, content_type="text/html")
            m.get.side_effect = side_effect
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("foreignobject" in r["type"].lower() or "foreign" in r["type"].lower() for r in warns))

    # ── SVG with external <use> ───────────────────────────────────────────────

    def test_svg_with_external_use_warns(self):
        svg = '<svg><use href="https://evil.com/icons.svg#arrow"/></svg>'
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if u.endswith(".svg"):
                    return _svg_resp(svg)
                return _svg_resp("", status=404, content_type="text/html")
            m.get.side_effect = side_effect
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("use" in r["type"].lower() or "external" in r["type"].lower() for r in warns))

    # ── Clean SVG passes ──────────────────────────────────────────────────────

    def test_clean_svg_passes(self):
        svg = '<svg xmlns="http://www.w3.org/2000/svg"><circle cx="50" cy="50" r="40" fill="blue"/></svg>'
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if u.endswith("/logo.svg"):
                    return _svg_resp(svg)
                return _svg_resp("", status=404, content_type="text/html")
            m.get.side_effect = side_effect
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))
