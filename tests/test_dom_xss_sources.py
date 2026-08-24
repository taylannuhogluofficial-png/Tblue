"""Tests for DOM XSS Source-to-Sink scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestDOMXSSSourcesScanner:
    def _scanner(self):
        from tblue.scanner.dom_xss_sources import DOMXSSSourcesScanner
        return DOMXSSSourcesScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        r.url = URL
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_page_passes(self):
        s = self._scanner()
        body = "<html><body><script>const x = 1;</script></body></html>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        assert all(r["status"] == "PASS" for r in results)

    def test_location_hash_to_innerhtml_fails(self):
        """location.hash → innerHTML = FAIL."""
        s = self._scanner()
        body = '<script>document.getElementById("out").innerHTML = location.hash.slice(1);</script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("location" in r["type"].lower() or "hash" in r["type"].lower() for r in fails)

    def test_location_search_to_innerhtml_fails(self):
        """location.search → innerHTML = FAIL."""
        s = self._scanner()
        body = '<script>el.innerHTML = location.search.replace("?q=", "");</script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails

    def test_document_referrer_to_innerhtml_fails(self):
        """document.referrer → innerHTML = FAIL."""
        s = self._scanner()
        body = '<script>container.innerHTML = document.referrer;</script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails

    def test_location_hash_to_eval_fails(self):
        """location.hash → eval = FAIL."""
        s = self._scanner()
        body = '<script>eval(location.hash.slice(1));</script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails

    def test_window_name_to_innerhtml_fails(self):
        """window.name → innerHTML = FAIL."""
        s = self._scanner()
        body = '<script>document.body.innerHTML = window.name;</script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails

    def test_result_structure(self):
        s = self._scanner()
        body = "<html><body><p>Hello</p></body></html>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_scan_js_hash_innerhtml(self):
        from tblue.scanner.dom_xss_sources import _scan_js
        js = 'el.innerHTML = location.hash.slice(1);'
        findings = _scan_js(js, "test")
        assert any(f["severity"] == "FAIL" for f in findings)

    def test_scan_js_search_innerhtml(self):
        from tblue.scanner.dom_xss_sources import _scan_js
        js = 'div.innerHTML = location.search.replace("?x=", "");'
        findings = _scan_js(js, "test")
        assert any(f["severity"] == "FAIL" for f in findings)

    def test_scan_js_clean_code(self):
        from tblue.scanner.dom_xss_sources import _scan_js
        js = "const x = 1; function add(a,b){ return a+b; } console.log(add(2,3));"
        findings = _scan_js(js, "test")
        assert not findings

    def test_scan_js_hash_eval(self):
        from tblue.scanner.dom_xss_sources import _scan_js
        js = "eval(location.hash.replace('#', ''));"
        findings = _scan_js(js, "test")
        assert any(f["severity"] == "FAIL" for f in findings)
