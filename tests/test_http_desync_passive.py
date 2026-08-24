"""Tests for HTTP Desync Passive scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestHTTPDesyncPassiveScanner:
    def _scanner(self):
        from tblue.scanner.http_desync_passive import HTTPDesyncPassiveScanner
        return HTTPDesyncPassiveScanner(MagicMock())

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

    def test_clean_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp({"content-type": "text/html"})):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_te_cl_both_present_warns(self):
        s = self._scanner()
        headers = {
            "content-length": "1234",
            "transfer-encoding": "chunked",
            "content-type": "text/html",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("te_cl" in r["type"] or "desync" in r["type"] for r in warns)

    def test_multi_hop_proxy_warns(self):
        s = self._scanner()
        headers = {"via": "1.1 proxy1, 1.1 proxy2, 1.1 proxy3"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("multi_hop" in r["type"] or "proxy" in r["type"] for r in warns)

    def test_mixed_stack_warns(self):
        s = self._scanner()
        headers = {
            "server": "nginx/1.24.0",
            "x-forwarded-for": "1.2.3.4",
        }
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("mixed_stack" in r["type"] or "desync" in r["type"] for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_te_cl_surface_both(self):
        from tblue.scanner.http_desync_passive import _check_te_cl_surface
        result = _check_te_cl_surface(
            {"content-length": "100", "transfer-encoding": "chunked"}, URL
        )
        assert result is not None

    def test_te_cl_surface_only_cl(self):
        from tblue.scanner.http_desync_passive import _check_te_cl_surface
        assert _check_te_cl_surface({"content-length": "100"}, URL) is None

    def test_proxy_chain_single(self):
        from tblue.scanner.http_desync_passive import _check_proxy_chain
        assert _check_proxy_chain({"via": "1.1 proxy1"}, URL) is None

    def test_proxy_chain_multi(self):
        from tblue.scanner.http_desync_passive import _check_proxy_chain
        result = _check_proxy_chain({"via": "1.1 p1, 1.1 p2"}, URL)
        assert result is not None
