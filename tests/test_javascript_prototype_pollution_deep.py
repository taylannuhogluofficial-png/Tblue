"""Tests for JavaScript Prototype Pollution Deep scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestJavaScriptPrototypePollutionDeepScanner:
    def _scanner(self):
        from tblue.scanner.javascript_prototype_pollution_deep import JavaScriptPrototypePollutionDeepScanner
        return JavaScriptPrototypePollutionDeepScanner(MagicMock())

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

    def test_clean_js_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("console.log('hello');")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_proto_direct_access_fails(self):
        s = self._scanner()
        body = "obj.__proto__.polluted = true;"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("proto_direct" in r["type"] for r in fails)

    def test_constructor_proto_fails(self):
        s = self._scanner()
        body = "obj.constructor.prototype.evil = 1;"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("constructor_proto" in r["type"] for r in fails)

    def test_jquery_extend_deep_warns(self):
        s = self._scanner()
        body = "$.extend(true, target, source);"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("jquery" in r["type"] for r in warns)

    def test_lodash_merge_warns(self):
        s = self._scanner()
        body = "_.merge(target, userInput);"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("lodash" in r["type"] for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_scan_js_proto_direct(self):
        from tblue.scanner.javascript_prototype_pollution_deep import _scan_js_for_pp_gadgets
        findings = _scan_js_for_pp_gadgets("obj.__proto__.x = 1", URL)
        assert any("proto_direct" in f["type"] for f in findings)

    def test_scan_js_clean(self):
        from tblue.scanner.javascript_prototype_pollution_deep import _scan_js_for_pp_gadgets
        assert _scan_js_for_pp_gadgets("const x = 1;", URL) == []

    def test_scan_js_constructor_prototype(self):
        from tblue.scanner.javascript_prototype_pollution_deep import _scan_js_for_pp_gadgets
        findings = _scan_js_for_pp_gadgets("obj.constructor.prototype.evil = true", URL)
        assert any("constructor_proto" in f["type"] for f in findings)
