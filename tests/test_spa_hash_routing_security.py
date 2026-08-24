"""Tests for SPA Hash Routing Security scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestSPAHashRoutingSecurityScanner:
    def _scanner(self):
        from tblue.scanner.spa_hash_routing_security import SPAHashRoutingSecurityScanner
        return SPAHashRoutingSecurityScanner(MagicMock())

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

    def test_clean_page_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>OK</html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_fragment_xss_sink_fails(self):
        s = self._scanner()
        body = "element.innerHTML += location.hash.substring(1);"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("dom_xss" in r["type"] for r in fails)

    def test_open_redirect_via_hash_warns(self):
        s = self._scanner()
        body = "location.href = location.hash.replace('#', '');"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        found = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("redirect" in r["type"] or "hash" in r["type"] for r in found)

    def test_hash_router_warns(self):
        s = self._scanner()
        body = "const router = createHashHistory();"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        found = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("hash" in r["type"] or "router" in r["type"] for r in found)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_fragment_xss_detected(self):
        from tblue.scanner.spa_hash_routing_security import _scan_for_hash_routing_issues
        findings = _scan_for_hash_routing_issues(
            "div.innerHTML += location.hash", URL
        )
        assert any("xss" in f["type"] for f in findings)

    def test_clean_js(self):
        from tblue.scanner.spa_hash_routing_security import _scan_for_hash_routing_issues
        assert _scan_for_hash_routing_issues("const x = 1;", URL) == []
