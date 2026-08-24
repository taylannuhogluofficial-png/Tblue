"""Tests for CORS Wildcard API scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestCORSWildcardAPIScanner:
    def _scanner(self):
        from tblue.scanner.cors_wildcard_api import CORSWildcardAPIScanner
        return CORSWildcardAPIScanner(MagicMock())

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

    def test_clean_cors_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"content-type": "application/json"})):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_wildcard_cors_on_api_warns(self):
        s = self._scanner()

        def get_side(url, **kwargs):
            if "/api" in url:
                return self._resp({"access-control-allow-origin": "*"})
            return self._resp({"content-type": "text/html"})

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        found = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("wildcard" in r["type"] for r in found)

    def test_reflected_origin_with_credentials_fails(self):
        s = self._scanner()

        def get_side(url, headers=None, **kwargs):
            h = headers or {}
            origin = h.get("Origin", "")
            if "/api" in url and "attacker.tbl9z7x-probe" in origin:
                return self._resp({
                    "access-control-allow-origin": origin,
                    "access-control-allow-credentials": "true",
                })
            return self._resp({"content-type": "text/html"})

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("reflection" in r["type"] or "cors" in r["type"] for r in fails)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
