"""Tests for ETag Fingerprinting scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestETagFingerprintingScanner:
    def _scanner(self):
        from tblue.scanner.etag_fingerprinting import ETagFingerprintingScanner
        return ETagFingerprintingScanner(MagicMock())

    def _resp(self, etag="", status=200):
        r = MagicMock()
        r.text = "<html></html>"
        r.status_code = status
        r.headers = {"etag": etag} if etag else {}
        r.url = URL
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_etag_passes(self):
        """No ETag headers on any path → PASS."""
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("")):
            results = s.scan(URL)
        assert all(r["status"] == "PASS" for r in results)
        assert any("no ETag" in r["type"] for r in results)

    def test_apache_inode_etag_warns(self):
        """Apache-style inode-size-mtime ETag → WARN."""
        s = self._scanner()
        # Apache format: "inode-size-mtime" all hex
        apache_etag = '"5f3a2b1c-1a2b-3c4d5e6f"'
        with patch.object(s.http, "get", return_value=self._resp(apache_etag)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("inode" in r["type"].lower() or "Apache" in r["type"] for r in warns)

    def test_sequential_numeric_etag_warns(self):
        """Pure numeric ETag → WARN (sequential counter risk)."""
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp('"12345"')):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("numeric" in r["type"].lower() or "sequential" in r["type"].lower() for r in warns)

    def test_etag_on_404_warns(self):
        """ETag present on 404 response → WARN."""
        s = self._scanner()
        resp_404 = self._resp('"some-etag-value"', status=404)
        resp_200 = self._resp("")
        resp_200.status_code = 200
        resp_200.headers = {}

        call_count = {"n": 0}
        def get_side(url):
            call_count["n"] += 1
            if "tbl9z7x" in url:  # 404 probe path
                return resp_404
            return resp_200

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("404" in r["type"] for r in warns)

    def test_good_hash_etag_passes(self):
        """Proper hash-based ETag (not matching any fingerprinting patterns) → PASS."""
        s = self._scanner()
        # A realistic SHA-based ETag
        etag = '"a3f5b7c9e1d3f5b7"'
        with patch.object(s.http, "get", return_value=self._resp(etag)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        # Should not FAIL on a proper hash ETag
        assert not fails

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("")):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_normalize_etag_strips_weak_prefix(self):
        from tblue.scanner.etag_fingerprinting import _normalize_etag
        assert _normalize_etag('W/"abc123"') == "abc123"

    def test_normalize_etag_strips_quotes(self):
        from tblue.scanner.etag_fingerprinting import _normalize_etag
        assert _normalize_etag('"hello"') == "hello"

    def test_apache_etag_regex_matches(self):
        from tblue.scanner.etag_fingerprinting import _APACHE_ETAG_RE
        # Real Apache format: three hex groups separated by dashes
        assert _APACHE_ETAG_RE.match("5f3a2b1c-1a2b-3c4d5e6f")

    def test_numeric_etag_regex_matches(self):
        from tblue.scanner.etag_fingerprinting import _NUMERIC_ETAG_RE
        assert _NUMERIC_ETAG_RE.match('"42"')
        assert _NUMERIC_ETAG_RE.match("1234567890")

    def test_uuid_etag_regex_matches(self):
        from tblue.scanner.etag_fingerprinting import _UUID_ETAG_RE
        assert _UUID_ETAG_RE.match('"550e8400-e29b-41d4-a716-446655440000"')
