"""Tests for Deep CORS Misconfiguration scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestCORSMisconfigurationDeepScanner:
    def _scanner(self):
        from tblue.scanner.cors_misconfiguration_deep import CORSMisconfigurationDeepScanner
        return CORSMisconfigurationDeepScanner(MagicMock())

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        r.url = URL
        return r

    def test_no_cors_headers_passes(self):
        """Server without CORS headers → PASS (no misconfig)."""
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_null_origin_with_credentials_fails(self):
        """ACAO: null + ACAC: true → FAIL."""
        s = self._scanner()
        headers = {
            "access-control-allow-origin": "null",
            "access-control-allow-credentials": "true",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers=headers)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("null" in r["type"].lower() for r in fails)

    def test_wildcard_with_credentials_fails(self):
        """ACAO: * + ACAC: true → FAIL."""
        s = self._scanner()
        headers = {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers=headers)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("wildcard" in r["type"].lower() or "credentials" in r["type"].lower() for r in fails)

    def test_vary_origin_absent_warns(self):
        """Dynamic ACAO without Vary: Origin → WARN."""
        s = self._scanner()
        headers = {
            "access-control-allow-origin": "https://trusted.example.com",
            "vary": "Accept-Encoding",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers=headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("vary" in r["type"].lower() for r in warns)

    def test_vary_origin_present_passes(self):
        """Dynamic ACAO with Vary: Origin → no Vary warning."""
        s = self._scanner()
        headers = {
            "access-control-allow-origin": "https://trusted.example.com",
            "vary": "Origin, Accept-Encoding",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers=headers)):
            results = s.scan(URL)
        vary_warns = [r for r in results if "vary" in r.get("type", "").lower()
                      and r["status"] == "WARN"]
        assert not vary_warns

    def test_origin_bypass_suffix_fails(self):
        """Suffix bypass: example.com.evil.com reflected → FAIL or WARN."""
        s = self._scanner()

        def get_side(url, headers=None, **kwargs):
            origin = (headers or {}).get("Origin", "")
            resp_headers = {}
            if "evil.com" in origin:
                resp_headers = {
                    "access-control-allow-origin": origin,
                    "access-control-allow-credentials": "true",
                }
            return self._resp(headers=resp_headers)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        bad = [r for r in results if r["status"] in ("FAIL", "WARN")
               and "bypass" in r.get("type", "").lower()]
        assert bad

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_build_bypass_origins(self):
        from tblue.scanner.cors_misconfiguration_deep import _build_bypass_origins
        origins = _build_bypass_origins("example.com")
        assert any("evil.com" in o for o in origins)
        assert any("http://" in o for o in origins)

    def test_check_null_origin_no_creds(self):
        """null origin without credentials → no finding."""
        from tblue.scanner.cors_misconfiguration_deep import _check_null_origin
        http = MagicMock()
        resp = MagicMock()
        resp.headers = {"access-control-allow-origin": "null"}
        http.get.return_value = resp
        result = _check_null_origin(http, "https://example.com")
        assert result is None

    def test_check_null_origin_with_creds_fails(self):
        from tblue.scanner.cors_misconfiguration_deep import _check_null_origin
        http = MagicMock()
        resp = MagicMock()
        resp.headers = {
            "access-control-allow-origin": "null",
            "access-control-allow-credentials": "true",
        }
        http.get.return_value = resp
        result = _check_null_origin(http, "https://example.com")
        assert result is not None
        assert result["status"] == "FAIL"

    def test_check_vary_origin_absent(self):
        from tblue.scanner.cors_misconfiguration_deep import _check_vary_origin_absent
        http = MagicMock()
        resp = MagicMock()
        resp.headers = {
            "access-control-allow-origin": "https://partner.com",
            "vary": "Accept",
        }
        http.get.return_value = resp
        result = _check_vary_origin_absent(http, "https://example.com")
        assert result is not None
        assert result["status"] == "WARN"

    def test_check_vary_origin_present(self):
        from tblue.scanner.cors_misconfiguration_deep import _check_vary_origin_absent
        http = MagicMock()
        resp = MagicMock()
        resp.headers = {
            "access-control-allow-origin": "https://partner.com",
            "vary": "Origin, Accept",
        }
        http.get.return_value = resp
        result = _check_vary_origin_absent(http, "https://example.com")
        assert result is None
