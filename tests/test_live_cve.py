"""Tests for live_cve scanner and cve_feed module — all network calls mocked."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


# ── cve_feed unit tests ────────────────────────────────────────────────────────

class TestCVEFeed:
    def test_parse_nvd_response_empty(self):
        from tblue.cve_feed import _parse_nvd_response
        result = _parse_nvd_response({})
        assert result == []

    def test_parse_nvd_response_with_cve(self):
        from tblue.cve_feed import _parse_nvd_response
        data = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2023-1234",
                    "published": "2023-06-01T00:00:00.000",
                    "descriptions": [{"lang": "en", "value": "Critical vulnerability in example"}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {"baseScore": 9.8}
                        }]
                    },
                    "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234"}],
                    "configurations": [],
                }
            }]
        }
        result = _parse_nvd_response(data)
        assert len(result) == 1
        assert result[0]["id"] == "CVE-2023-1234"
        assert result[0]["score"] == 9.8
        assert result[0]["severity"] == "CRITICAL"

    def test_parse_osv_response_empty(self):
        from tblue.cve_feed import _parse_osv_response
        result = _parse_osv_response({})
        assert result == []

    def test_parse_osv_response_with_vuln(self):
        from tblue.cve_feed import _parse_osv_response
        data = {
            "vulns": [{
                "id": "GHSA-xxxx-xxxx-xxxx",
                "aliases": ["CVE-2023-5678"],
                "summary": "Prototype pollution in example package",
                "details": "Detailed description here.",
                "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                "affected": [{"ranges": [{"events": [{"fixed": "2.0.0"}]}]}],
                "references": [{"url": "https://github.com/advisories/GHSA-xxxx"}],
                "published": "2023-07-01T00:00:00Z",
            }]
        }
        result = _parse_osv_response(data)
        assert len(result) == 1
        assert result[0]["id"] == "CVE-2023-5678"
        assert result[0]["affected_versions"] == ["< 2.0.0"]

    def test_nvd_severity_thresholds(self):
        from tblue.cve_feed import _nvd_severity
        assert _nvd_severity(9.8) == "CRITICAL"
        assert _nvd_severity(8.0) == "HIGH"
        assert _nvd_severity(5.0) == "MEDIUM"
        assert _nvd_severity(2.0) == "LOW"

    def test_cache_read_miss(self):
        """Cache miss returns None."""
        from tblue.cve_feed import _cache_read
        with patch("tblue.cve_feed._CACHE_DIR", "/tmp/nonexistent_tbl_cache"):
            result = _cache_read("nonexistent_key_xyz")
        assert result is None

    def test_cache_write_read_roundtrip(self, tmp_path):
        """Written cache is readable."""
        import tblue.cve_feed as feed
        original_dir = feed._CACHE_DIR
        feed._CACHE_DIR = str(tmp_path)
        try:
            feed._cache_write("testkey", [{"id": "CVE-2023-0001", "score": 7.5}])
            result = feed._cache_read("testkey")
            assert result is not None
            assert result[0]["id"] == "CVE-2023-0001"
        finally:
            feed._CACHE_DIR = original_dir

    def test_query_cves_uses_osv_for_pypi(self):
        """query_cves calls OSV for known PyPI packages."""
        from tblue.cve_feed import query_cves
        mock_result = [{"id": "CVE-2023-9999", "score": 8.5, "severity": "HIGH",
                        "description": "desc", "references": [], "affected_versions": ["< 4.0"],
                        "source": "OSV", "published": "2023-01-01"}]
        with patch("tblue.cve_feed.query_osv", return_value=mock_result) as mock_osv:
            with patch("tblue.cve_feed.query_nvd_keyword", return_value=[]):
                result = query_cves("django", "3.2.0")
        mock_osv.assert_called_once_with("django", "3.2.0", "PyPI")
        assert result[0]["id"] == "CVE-2023-9999"

    def test_query_cves_uses_nvd_for_unknown(self):
        """query_cves falls back to NVD keyword search for unknown ecosystem."""
        from tblue.cve_feed import query_cves
        mock_result = [{"id": "CVE-2023-0042", "score": 9.0, "severity": "CRITICAL",
                        "description": "desc", "references": [], "affected_versions": [],
                        "source": "NVD", "published": "2023-01-01"}]
        with patch("tblue.cve_feed.query_nvd_keyword", return_value=mock_result) as mock_nvd:
            with patch("tblue.cve_feed.query_osv", return_value=[]):
                result = query_cves("customfw", "1.0.0")
        mock_nvd.assert_called_once()
        assert result[0]["id"] == "CVE-2023-0042"

    def test_match_version_cves_returns_findings(self):
        """match_version_cves returns formatted findings."""
        from tblue.cve_feed import match_version_cves
        mock_cves = [{"id": "CVE-2023-1111", "score": 9.8, "severity": "CRITICAL",
                      "description": "Remote code execution", "references": ["https://nvd.nist.gov"],
                      "affected_versions": ["< 3.2.19"], "source": "NVD", "published": "2023-05-01"}]
        detected = [{"package": "django", "version": "3.2.0", "location": URL}]
        with patch("tblue.cve_feed.query_cves", return_value=mock_cves):
            findings = match_version_cves(URL, detected)
        assert len(findings) == 1
        assert findings[0]["status"] == "FAIL"
        assert "CVE-2023-1111" in findings[0]["type"]

    def test_match_version_cves_medium_is_warn(self):
        """CVSS < 7.0 → WARN not FAIL."""
        from tblue.cve_feed import match_version_cves
        mock_cves = [{"id": "CVE-2023-2222", "score": 5.0, "severity": "MEDIUM",
                      "description": "Info disclosure", "references": [],
                      "affected_versions": [], "source": "OSV", "published": "2023-03-01"}]
        detected = [{"package": "flask", "version": "2.0.0", "location": URL}]
        with patch("tblue.cve_feed.query_cves", return_value=mock_cves):
            findings = match_version_cves(URL, detected)
        assert findings[0]["status"] == "WARN"


# ── LiveCVEScanner tests ───────────────────────────────────────────────────────

class TestLiveCVEScanner:
    def _scanner(self):
        from tblue.scanner.live_cve import LiveCVEScanner
        return LiveCVEScanner(MagicMock())

    def _resp(self, body="", headers=None, status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        r.url = URL
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_versions_detected_passes(self):
        """Page with no version strings → PASS."""
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html><body>Hello</body></html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" and "no detectable" in r["type"].lower() for r in results)

    def test_nginx_version_detected_and_queried(self):
        """nginx version in Server header → queried, CVE returned → FAIL."""
        s = self._scanner()
        headers = {"Server": "nginx/1.14.0"}
        mock_cve = [{"id": "CVE-2019-9511", "score": 7.5, "severity": "HIGH",
                     "description": "HTTP/2 DoS", "references": [],
                     "affected_versions": ["< 1.15.6"], "source": "NVD", "published": "2019-08-13"}]

        with patch.object(s.http, "get", return_value=self._resp("<html></html>", headers=headers)):
            with patch("tblue.scanner.live_cve.match_version_cves", return_value=[
                {"url": URL, "type": "Live CVE — CVE-2019-9511 (HIGH) in nginx 1.14.0",
                 "status": "FAIL", "detail": "...", "cve_id": "CVE-2019-9511",
                 "cvss_score": 7.5, "package": "nginx", "version": "1.14.0"}
            ]):
                results = s.scan(URL)

        fails = [r for r in results if r["status"] == "FAIL" and "CVE" in r.get("type", "")]
        assert fails

    def test_no_cves_found_passes(self):
        """Versions detected but no CVEs in feed → PASS."""
        s = self._scanner()
        headers = {"Server": "nginx/1.27.0"}

        with patch.object(s.http, "get", return_value=self._resp("<html></html>", headers=headers)):
            with patch("tblue.scanner.live_cve.match_version_cves", return_value=[]):
                results = s.scan(URL)

        passes = [r for r in results if r["status"] == "PASS" and "no CVEs" in r["type"]]
        assert passes

    def test_jquery_version_in_body_detected(self):
        """jquery version in page body is detected."""
        s = self._scanner()
        body = '<script src="/js/jquery-1.12.4.min.js"></script>'

        with patch.object(s.http, "get", return_value=self._resp(body)):
            with patch("tblue.scanner.live_cve.match_version_cves", return_value=[]) as mock_match:
                s.scan(URL)

        # Verify jquery was detected and passed to match_version_cves
        called_versions = mock_match.call_args[0][1] if mock_match.call_args else []
        packages = [v["package"] for v in called_versions]
        assert "jquery" in packages

    def test_wordpress_meta_tag_detected(self):
        """WordPress version in meta generator tag is detected."""
        s = self._scanner()
        body = '<meta name="generator" content="WordPress 5.8.1">'

        with patch.object(s.http, "get", return_value=self._resp(body)):
            with patch("tblue.scanner.live_cve.match_version_cves", return_value=[]) as mock_match:
                s.scan(URL)

        called_versions = mock_match.call_args[0][1] if mock_match.call_args else []
        packages = [v["package"] for v in called_versions]
        assert "wordpress" in packages

    def test_result_structure(self):
        """All results have required keys."""
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html></html>")):
            results = s.scan(URL)
        for r in results:
            assert "url" in r or r.get("type")
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")
