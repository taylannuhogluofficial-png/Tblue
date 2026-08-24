"""Tests for Cross-Origin Policy Deep scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestCrossOriginPolicyDeepScanner:
    def _scanner(self):
        from tblue.scanner.cross_origin_policy_deep import CrossOriginPolicyDeepScanner
        return CrossOriginPolicyDeepScanner(MagicMock())

    def _resp(self, headers=None, status=200):
        r = MagicMock()
        r.text = ""
        r.status_code = status
        r.headers = headers or {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_all_headers_missing_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"content-type": "text/html"})):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert len(warns) >= 3

    def test_coop_missing_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"content-type": "text/html"})):
            results = s.scan(URL)
        assert any("coop-missing" in r["type"] for r in results)

    def test_coep_missing_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"content-type": "text/html"})):
            results = s.scan(URL)
        assert any("coep-missing" in r["type"] for r in results)

    def test_corp_missing_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"content-type": "text/html"})):
            results = s.scan(URL)
        assert any("corp-missing" in r["type"] for r in results)

    def test_all_headers_present_passes(self):
        s = self._scanner()
        headers = {
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-embedder-policy": "require-corp",
            "cross-origin-resource-policy": "same-origin",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)
        assert not any(r["status"] in ("WARN", "FAIL") for r in results)

    def test_coop_unsafe_none_warns(self):
        s = self._scanner()
        headers = {
            "cross-origin-opener-policy": "unsafe-none",
            "cross-origin-embedder-policy": "require-corp",
            "cross-origin-resource-policy": "same-site",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        assert any("unsafe-none" in r["type"] for r in results)

    def test_corp_cross_origin_warns(self):
        s = self._scanner()
        headers = {
            "cross-origin-opener-policy": "same-origin",
            "cross-origin-embedder-policy": "require-corp",
            "cross-origin-resource-policy": "cross-origin",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        assert any("cross-origin" in r["type"] for r in results)

    def test_coop_report_only_warns(self):
        s = self._scanner()
        headers = {
            "cross-origin-opener-policy-report-only": "same-origin",
            "cross-origin-embedder-policy": "require-corp",
            "cross-origin-resource-policy": "same-origin",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        assert any("report-only" in r["type"] for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_coop_missing(self):
        from tblue.scanner.cross_origin_policy_deep import _check_coop
        result = _check_coop({}, URL)
        assert result is not None
        assert "missing" in result["type"]

    def test_check_coop_present(self):
        from tblue.scanner.cross_origin_policy_deep import _check_coop
        result = _check_coop({"cross-origin-opener-policy": "same-origin"}, URL)
        assert result is None

    def test_check_coep_missing(self):
        from tblue.scanner.cross_origin_policy_deep import _check_coep
        result = _check_coep({}, URL)
        assert result is not None

    def test_check_corp_cross_origin(self):
        from tblue.scanner.cross_origin_policy_deep import _check_corp
        result = _check_corp({"cross-origin-resource-policy": "cross-origin"}, URL)
        assert result is not None
