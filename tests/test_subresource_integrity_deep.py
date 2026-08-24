"""Tests for Subresource Integrity Deep scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestSubresourceIntegrityDeepScanner:
    def _scanner(self):
        from tblue.scanner.subresource_integrity_deep import SubresourceIntegrityDeepScanner
        return SubresourceIntegrityDeepScanner(MagicMock())

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

    def test_no_external_resources_passes(self):
        s = self._scanner()
        body = '<html><script src="/local.js"></script></html>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_external_script_without_sri_warns(self):
        s = self._scanner()
        body = '<html><script src="https://cdn.example.net/lib.js"></script></html>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("sri_missing" in r["type"] for r in warns)

    def test_external_script_with_sri_passes(self):
        s = self._scanner()
        body = (
            '<html><script src="https://cdn.example.net/lib.js" '
            'integrity="sha384-abc123" crossorigin="anonymous"></script></html>'
        )
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_weak_sha1_sri_warns(self):
        s = self._scanner()
        body = (
            '<html><script src="https://cdn.example.net/lib.js" '
            'integrity="sha1-abc123" crossorigin="anonymous"></script></html>'
        )
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("weak_hash" in r["type"] for r in warns)

    def test_sri_without_crossorigin_warns(self):
        s = self._scanner()
        body = (
            '<html><script src="https://cdn.example.net/lib.js" '
            'integrity="sha384-abc123"></script></html>'
        )
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("crossorigin" in r["type"] for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_extract_external_resources(self):
        from tblue.scanner.subresource_integrity_deep import _extract_external_resources
        body = '<script src="https://cdn.example.net/lib.js"></script>'
        resources = _extract_external_resources(body, "example.com")
        assert len(resources) == 1

    def test_extract_local_only(self):
        from tblue.scanner.subresource_integrity_deep import _extract_external_resources
        body = '<script src="/local.js"></script>'
        assert _extract_external_resources(body, "example.com") == []
