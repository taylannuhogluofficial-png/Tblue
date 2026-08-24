"""Tests for SrcdocInjectionScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.srcdoc_injection import SrcdocInjectionScanner

URL = "https://example.com"


class TestSrcdocInjection:
    def _scanner(self):
        return SrcdocInjectionScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_javascript_src_iframe_fails(self):
        body = '<iframe src="javascript:alert(1)"></iframe>'
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("javascript" in r["type"] for r in fails)

    def test_data_url_iframe_warns(self):
        body = '<iframe src="data:text/html,<h1>Test</h1>"></iframe>'
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        issues = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("data_url" in r["type"] for r in issues)

    def test_srcdoc_with_script_fails(self):
        body = '<iframe srcdoc="<script>alert(1)</script>"></iframe>'
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("script" in r["type"] for r in fails)

    def test_srcdoc_from_url_param_fails(self):
        body = "el.srcdoc = location.search.slice(1);"
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("param" in r["type"] or "url_param" in r["type"] for r in fails)

    def test_srcdoc_without_sandbox_warns(self):
        body = '<iframe srcdoc="<p>Static content</p>"></iframe>'
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        issues = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("sandbox" in r["type"] for r in issues)

    def test_clean_page_passes(self):
        body = "<html><body><p>No iframes here</p></body></html>"
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("OK")):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
