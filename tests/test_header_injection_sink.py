"""Tests for Header Injection Sink scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestHeaderInjectionSinkScanner:
    def _scanner(self):
        from tblue.scanner.header_injection_sink import HeaderInjectionSinkScanner
        return HeaderInjectionSinkScanner(MagicMock())

    def _resp(self, headers=None, status=200, text="<html></html>"):
        r = MagicMock()
        r.status_code = status
        r.text = text
        r.url = URL
        h = headers or {}
        r.headers.get = lambda k, d="": h.get(k.lower(), d)
        r.headers.items = lambda: h.items()
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_reflection_passes(self):
        """Normal headers, no probe value reflected → PASS."""
        s = self._scanner()
        normal_resp = self._resp({"content-type": "text/html", "server": "nginx"})
        with patch.object(s.http, "get", return_value=normal_resp):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_probe_reflected_in_header_warns(self):
        """Probe value appears in a response header → WARN."""
        s = self._scanner()
        from tblue.scanner.header_injection_sink import _PROBE_VALUE

        def side(url, headers=None):
            if _PROBE_VALUE in url:
                return self._resp({"location": f"/redirect?to={_PROBE_VALUE}"}, 302)
            return self._resp()

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        non_pass = [r for r in results if r["status"] != "PASS"]
        assert non_pass

    def test_cors_origin_reflection_fails(self):
        """CORS echoes Origin header value → FAIL."""
        s = self._scanner()
        evil_origin = "https://evil-tbl9z7x.com"

        def side(url, headers=None):
            origin = (headers or {}).get("Origin", "")
            if origin == evil_origin:
                return self._resp({"access-control-allow-origin": evil_origin})
            return self._resp()

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("cors" in r["type"].lower() for r in fails)

    def test_open_redirect_in_location_fails(self):
        """Location header reflects evil domain → FAIL."""
        s = self._scanner()

        def side(url, headers=None):
            if "example-evil-tbl9z7x.com" in url:
                return self._resp(
                    {"location": "https://example-evil-tbl9z7x.com/phishing"},
                    302
                )
            return self._resp()

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("location" in r["type"].lower() or "reflects" in r["type"].lower() for r in fails)

    def test_result_structure(self):
        s = self._scanner()
        normal = self._resp({"content-type": "text/html"})
        with patch.object(s.http, "get", return_value=normal):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_reflection_found(self):
        from tblue.scanner.header_injection_sink import _check_reflection
        r = MagicMock()
        r.headers.items = lambda: [("Location", "/goto?tbl9z7xprobe")]
        assert _check_reflection(r, "tbl9z7xprobe") == "location"

    def test_check_reflection_not_found(self):
        from tblue.scanner.header_injection_sink import _check_reflection
        r = MagicMock()
        r.headers.items = lambda: [("Content-Type", "text/html"), ("Server", "nginx")]
        assert _check_reflection(r, "tbl9z7xprobe") is None

    def test_check_cors_reflection_true(self):
        from tblue.scanner.header_injection_sink import _check_cors_reflection
        r = MagicMock()
        r.headers.get = lambda k, d="": "https://evil-tbl9z7x.com" if k == "access-control-allow-origin" else d
        assert _check_cors_reflection(r, "https://evil-tbl9z7x.com")

    def test_check_cors_reflection_false(self):
        from tblue.scanner.header_injection_sink import _check_cors_reflection
        r = MagicMock()
        r.headers.get = lambda k, d="": "https://example.com" if k == "access-control-allow-origin" else d
        assert not _check_cors_reflection(r, "https://evil-tbl9z7x.com")
