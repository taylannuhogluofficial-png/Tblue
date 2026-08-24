"""Tests for CORS Deep Analysis scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestCORSDeepAnalysisScanner:
    def _scanner(self):
        from tblue.scanner.cors_deep_analysis import CORSDeepAnalysisScanner
        return CORSDeepAnalysisScanner(MagicMock())

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

    def test_no_cors_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"content-type": "text/html"})):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_wildcard_with_credentials_fails(self):
        s = self._scanner()
        headers = {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("wildcard" in r["type"] or "credentials" in r["type"] for r in fails)

    def test_null_origin_warns(self):
        s = self._scanner()
        headers = {"access-control-allow-origin": "null"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("null" in r["type"] for r in warns)

    def test_missing_vary_warns(self):
        s = self._scanner()
        headers = {"access-control-allow-origin": "https://trusted.com"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("vary" in r["type"] for r in warns)

    def test_vary_present_no_warn(self):
        s = self._scanner()
        headers = {
            "access-control-allow-origin": "https://trusted.com",
            "vary": "Origin",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        assert not any("vary" in r["type"] for r in results)

    def test_origin_reflection_warns(self):
        from tblue.scanner.cors_deep_analysis import _PROBE_ORIGIN
        s = self._scanner()
        probe_resp = self._resp({"access-control-allow-origin": _PROBE_ORIGIN})
        with patch.object(s.http, "get", return_value=probe_resp):
            results = s.scan(URL)
        assert any("reflection" in r["type"] for r in results)

    def test_origin_reflection_with_creds_fails(self):
        from tblue.scanner.cors_deep_analysis import _PROBE_ORIGIN
        s = self._scanner()
        probe_resp = self._resp({
            "access-control-allow-origin": _PROBE_ORIGIN,
            "access-control-allow-credentials": "true",
        })
        with patch.object(s.http, "get", return_value=probe_resp):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("reflection" in r["type"] for r in fails)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_wildcard_credentials(self):
        from tblue.scanner.cors_deep_analysis import _check_wildcard_credentials
        headers = {"access-control-allow-origin": "*", "access-control-allow-credentials": "true"}
        result = _check_wildcard_credentials(headers, URL)
        assert result is not None
        assert result["status"] == "FAIL"

    def test_check_null_origin(self):
        from tblue.scanner.cors_deep_analysis import _check_null_origin
        result = _check_null_origin({"access-control-allow-origin": "null"}, URL)
        assert result is not None

    def test_check_vary_missing(self):
        from tblue.scanner.cors_deep_analysis import _check_vary_origin
        headers = {"access-control-allow-origin": "https://a.com"}
        result = _check_vary_origin(headers, URL)
        assert result is not None

    def test_check_vary_present_ok(self):
        from tblue.scanner.cors_deep_analysis import _check_vary_origin
        headers = {"access-control-allow-origin": "https://a.com", "vary": "origin, accept"}
        result = _check_vary_origin(headers, URL)
        assert result is None
