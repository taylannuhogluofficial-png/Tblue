"""Tests for DNS CAA scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestDNSCAAScanner:
    def _scanner(self):
        from tblue.scanner.dns_caa import DNSCAAScanner
        return DNSCAAScanner(MagicMock())

    def test_no_caa_records_warns(self):
        """No CAA records found → WARN."""
        s = self._scanner()
        with patch("tblue.scanner.dns_caa._query_caa", return_value=[]):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("caa-missing" in r["type"].lower() or "caa" in r["type"].lower() for r in warns)

    def test_caa_records_present_passes(self):
        """Valid CAA records → PASS."""
        s = self._scanner()
        # (flag, tag, value)
        records = [(0, "issue", "letsencrypt.org"), (0, "iodef", "mailto:security@example.com")]
        with patch("tblue.scanner.dns_caa._query_caa", return_value=records):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_caa_without_iodef_warns(self):
        """CAA present but no iodef → WARN."""
        s = self._scanner()
        records = [(0, "issue", "letsencrypt.org")]
        with patch("tblue.scanner.dns_caa._query_caa", return_value=records):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("iodef" in r["type"].lower() for r in warns)

    def test_invalid_url_passes(self):
        """URL with no extractable hostname → PASS."""
        s = self._scanner()
        results = s.scan("not-a-url")
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch("tblue.scanner.dns_caa._query_caa", return_value=[]):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_get_parent_domains(self):
        from tblue.scanner.dns_caa import _get_parent_domains
        parents = _get_parent_domains("sub.example.com")
        assert "example.com" in parents

    def test_get_parent_domains_apex(self):
        from tblue.scanner.dns_caa import _get_parent_domains
        # For a 2-part domain, the function returns the full domain as the only entry
        parents = _get_parent_domains("example.com")
        assert isinstance(parents, list)

    def test_parse_caa_empty_data(self):
        from tblue.scanner.dns_caa import _parse_caa_response
        # Too short data → empty result
        result = _parse_caa_response(b"\x00\x01", 1)
        assert result == []

    def test_query_caa_handles_exception(self):
        """_query_caa returns empty list when DNS fails."""
        from tblue.scanner.dns_caa import _query_caa
        with patch("tblue.scanner.dns_caa._raw_caa_query", side_effect=Exception("DNS timeout")):
            result = _query_caa("nonexistent-tbl9z7x.invalid")
        assert result == []
