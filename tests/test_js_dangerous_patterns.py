"""Tests for JSDangerousPatternsScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.js_dangerous_patterns import JSDangerousPatternsScanner

URL = "https://example.com"


def _page(js):
    return f"<html><head></head><body><script>{js}</script></body></html>"


class TestJSDangerousPatterns(unittest.TestCase):
    def _make(self):
        s = JSDangerousPatternsScanner.__new__(JSDangerousPatternsScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", headers=None):
        r = MagicMock()
        r.status_code = 200
        r.text = body
        r.headers = headers or {}
        return r

    # ── eval() with tainted source ────────────────────────────────────────────

    def test_eval_with_location_hash_fails(self):
        body = _page("eval(location.hash.substr(1));")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("eval" in r["type"].lower() for r in fails))

    def test_eval_with_document_url_fails(self):
        body = _page("eval(document.URL.split('?')[1]);")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(len(fails) > 0)

    # ── new Function() ────────────────────────────────────────────────────────

    def test_new_function_warns(self):
        body = _page("var fn = new Function('return 1;')();")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("function" in r["type"].lower() or "eval" in r["type"].lower() for r in warns))

    # ── setTimeout with string ────────────────────────────────────────────────

    def test_settimeout_string_warns(self):
        body = _page("setTimeout('doSomething()', 1000);")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("settimeout" in r["type"].lower() or "setinterval" in r["type"].lower() or "string" in r["type"].lower() for r in warns))

    # ── innerHTML = location ──────────────────────────────────────────────────

    def test_innerhtml_with_location_fails(self):
        body = _page("el.innerHTML = location.hash.substring(1);")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("innerhtml" in r["type"].lower() or "dom xss" in r["type"].lower() or "sink" in r["type"].lower() for r in fails))

    # ── document.write with URL ───────────────────────────────────────────────

    def test_document_write_location_fails(self):
        body = _page("document.write('<img src=' + location.search + '>');")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("document.write" in r["type"].lower() or "dom xss" in r["type"].lower() or "sink" in r["type"].lower() for r in fails))

    # ── postMessage without origin check ─────────────────────────────────────

    def test_postmessage_no_origin_check_warns(self):
        body = _page("""
window.addEventListener('message', function(event) {
    var cmd = event.data.cmd;
    eval(cmd);
});
        """)
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("postmessage" in r["type"].lower() or "message" in r["type"].lower() or "origin" in r["type"].lower() for r in warns))

    # ── Dynamic script without SRI ────────────────────────────────────────────

    def test_dynamic_script_no_sri_warns(self):
        body = _page("""
var s = document.createElement('script');
s.src = 'https://cdn.external.com/lib.js';
document.head.appendChild(s);
        """)
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("sri" in r["type"].lower() or "script" in r["type"].lower() or "integrity" in r["type"].lower() for r in warns))

    # ── Clean page ────────────────────────────────────────────────────────────

    def test_safe_js_passes(self):
        body = _page("var x = document.getElementById('btn'); x.addEventListener('click', function() { fetch('/api/data'); });")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── No response ────────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
