"""Tests for Link Preview Exposure (SSRF via URL fetch) scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestLinkPreviewExposureScanner:
    def _scanner(self):
        from tblue.scanner.link_preview_exposure import LinkPreviewExposureScanner
        return LinkPreviewExposureScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        r.url = URL
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_preview_endpoints_passes(self):
        """All paths return 404 → PASS."""
        s = self._scanner()
        not_found = self._resp("<html>Not Found</html>", 404)
        with patch.object(s.http, "get", return_value=not_found):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_preview_endpoint_probe_reflected_fails(self):
        """Preview endpoint reflects probe value → FAIL."""
        s = self._scanner()
        from tblue.scanner.link_preview_exposure import _PROBE_MARKER

        def side(url):
            if "/api/preview" in url and _PROBE_MARKER in url:
                # Endpoint fetched the URL and returned its content
                return self._resp(f'{{"title": "probe={_PROBE_MARKER}"}}', 200)
            if "/api/preview" in url:
                return self._resp('{"error": "no url"}', 400)
            return self._resp("<html></html>", 404)

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("ssrf" in r["type"].lower() or "preview" in r["type"].lower() for r in fails)

    def test_oembed_endpoint_found_warns(self):
        """/oembed endpoint returning valid response → WARN."""
        s = self._scanner()

        def side(url):
            if "/oembed" in url:
                return self._resp('{"version": "1.0", "html": "<div></div>"}', 200)
            return self._resp("<html></html>", 404)

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("oembed" in r["type"].lower() for r in warns)

    def test_preview_endpoint_no_reflection_warns(self):
        """Preview endpoint exists but doesn't reflect probe → WARN (exists, not confirmed SSRF)."""
        s = self._scanner()

        def side(url):
            if "/api/preview" in url:
                return self._resp('{"title": "some title"}', 200)
            return self._resp("<html></html>", 404)

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        # Should at minimum WARN that the endpoint exists
        non_pass = [r for r in results if r["status"] != "PASS"]
        assert non_pass

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html></html>", 404)):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_endpoint_exists_true(self):
        from tblue.scanner.link_preview_exposure import _endpoint_exists
        r = MagicMock()
        r.status_code = 200
        assert _endpoint_exists(r)

    def test_endpoint_exists_false(self):
        from tblue.scanner.link_preview_exposure import _endpoint_exists
        r = MagicMock()
        r.status_code = 404
        assert not _endpoint_exists(r)

    def test_response_contains_probe(self):
        from tblue.scanner.link_preview_exposure import _response_contains_probe, _PROBE_MARKER
        r = MagicMock()
        r.text = f'{{"title": "probe={_PROBE_MARKER}"}}'
        assert _response_contains_probe(r)

    def test_response_not_contains_probe(self):
        from tblue.scanner.link_preview_exposure import _response_contains_probe
        r = MagicMock()
        r.text = '{"title": "hello world"}'
        assert not _response_contains_probe(r)
