"""Tests for Certificate Transparency Anomaly scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestCertificateTransparencyScanner:
    def _scanner(self):
        from tblue.scanner.certificate_transparency import CertificateTransparencyScanner
        return CertificateTransparencyScanner(MagicMock())

    def test_crtsh_unreachable_passes(self):
        s = self._scanner()
        with patch("tblue.scanner.certificate_transparency._query_crtsh", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_certs_passes(self):
        s = self._scanner()
        with patch("tblue.scanner.certificate_transparency._query_crtsh", return_value=[]):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_wildcard_cert_warns(self):
        s = self._scanner()
        certs = [
            {"name_value": "*.example.com", "issuer_name": "Let's Encrypt"},
            {"name_value": "example.com", "issuer_name": "Let's Encrypt"},
        ]
        with patch("tblue.scanner.certificate_transparency._query_crtsh", return_value=certs):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("wildcard" in r["type"].lower() for r in warns)

    def test_multiple_cas_warns(self):
        s = self._scanner()
        certs = [
            {"name_value": "example.com", "issuer_name": "Let's Encrypt Authority X3"},
            {"name_value": "example.com", "issuer_name": "DigiCert TLS RSA SHA256"},
            {"name_value": "example.com", "issuer_name": "Sectigo RSA DV"},
        ]
        with patch("tblue.scanner.certificate_transparency._query_crtsh", return_value=certs):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("ca" in r["type"].lower() or "issuer" in r["type"].lower() for r in warns)

    def test_clean_certs_passes(self):
        s = self._scanner()
        certs = [
            {"name_value": "example.com", "issuer_name": "Let's Encrypt Authority X3"},
            {"name_value": "www.example.com", "issuer_name": "Let's Encrypt Authority X3"},
        ]
        with patch("tblue.scanner.certificate_transparency._query_crtsh", return_value=certs):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch("tblue.scanner.certificate_transparency._query_crtsh", return_value=[]):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_analyze_certs_wildcard(self):
        from tblue.scanner.certificate_transparency import _analyze_certs
        certs = [{"name_value": "*.example.com", "issuer_name": "Let's Encrypt"}]
        findings = _analyze_certs(certs, "example.com")
        assert any("wildcard" in f["type"].lower() for f in findings)

    def test_analyze_certs_multiple_ca(self):
        from tblue.scanner.certificate_transparency import _analyze_certs
        certs = [
            {"name_value": "example.com", "issuer_name": "Let's Encrypt"},
            {"name_value": "example.com", "issuer_name": "DigiCert Inc"},
            {"name_value": "example.com", "issuer_name": "Sectigo Limited"},
        ]
        findings = _analyze_certs(certs, "example.com")
        assert any("ca" in f["type"].lower() for f in findings)

    def test_analyze_certs_clean(self):
        from tblue.scanner.certificate_transparency import _analyze_certs
        certs = [
            {"name_value": "example.com", "issuer_name": "Let's Encrypt"},
            {"name_value": "www.example.com", "issuer_name": "Let's Encrypt"},
        ]
        findings = _analyze_certs(certs, "example.com")
        assert findings == []
