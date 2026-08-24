"""Tests for Server-Timing Disclosure scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestServerTimingDisclosureScanner:
    def _scanner(self):
        from tblue.scanner.server_timing_disclosure import ServerTimingDisclosureScanner
        return ServerTimingDisclosureScanner(MagicMock())

    def _resp(self, body="OK", status=200, headers=None):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_timing_header_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("OK")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_internal_component_warns(self):
        from tblue.scanner.server_timing_disclosure import _analyze_timing_header
        findings = _analyze_timing_header("db;dur=25, render;dur=10", URL)
        assert any("internal" in f["type"] for f in findings)

    def test_slow_operation_warns(self):
        from tblue.scanner.server_timing_disclosure import _analyze_timing_header
        findings = _analyze_timing_header("total;dur=2500", URL)
        assert any("slow" in f["type"] for f in findings)

    def test_clean_timing_passes(self):
        from tblue.scanner.server_timing_disclosure import _analyze_timing_header
        findings = _analyze_timing_header("edge;dur=10, cdn-hit;desc=MISS", URL)
        assert findings == []

    def test_scanner_detects_timing_header(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(
            "OK", headers={"server-timing": "db;dur=45, auth;dur=12"}
        )):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("internal" in r["type"] for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
