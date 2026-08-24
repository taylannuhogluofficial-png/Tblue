"""Tests for TLS Certificate Deep scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"
HTTP_URL = "http://example.com"


class TestTLSCertificateDeepScanner:
    def _scanner(self):
        from tblue.scanner.tls_certificate_deep import TLSCertificateDeepScanner
        return TLSCertificateDeepScanner(MagicMock())

    def _resp(self, body="OK", status=200, headers=None):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        return r

    def test_http_url_skips(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(HTTP_URL)
        assert any("not_https" in r["type"] or r["status"] == "PASS" for r in results)

    def test_connect_error_warns(self):
        with patch("tblue.scanner.tls_certificate_deep._get_cert_info",
                   return_value={"cipher": None, "cert": None, "error": "Connection refused"}):
            s = self._scanner()
            with patch.object(s.http, "get", return_value=self._resp()):
                results = s.scan(URL)
        assert any(r["status"] in ("WARN", "PASS") for r in results)

    def test_clean_cert_passes(self):
        from datetime import datetime, timezone, timedelta
        future = (datetime.now(timezone.utc) + timedelta(days=200)).strftime("%b %d %H:%M:%S %Y %Z")
        fake_cert = {
            "notAfter": future,
            "subjectAltName": [("DNS", "example.com")],
            "subject": [[("commonName", "example.com")]],
        }
        with patch("tblue.scanner.tls_certificate_deep._get_cert_info",
                   return_value={"cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
                                 "cert": fake_cert, "error": None}):
            s = self._scanner()
            with patch.object(s.http, "get", return_value=self._resp()):
                results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_weak_cipher_fails(self):
        from tblue.scanner.tls_certificate_deep import _check_cipher
        findings = _check_cipher("RC4-MD5", URL)
        assert any("weak_cipher" in f["type"] for f in findings)

    def test_strong_cipher_passes(self):
        from tblue.scanner.tls_certificate_deep import _check_cipher
        findings = _check_cipher("TLS_AES_256_GCM_SHA384", URL)
        assert findings == []

    def test_expired_cert_fails(self):
        from tblue.scanner.tls_certificate_deep import _check_cert_validity
        findings = _check_cert_validity({
            "notAfter": "Jan  1 00:00:00 2020 GMT",
            "subjectAltName": [("DNS", "example.com")],
            "subject": [[("commonName", "example.com")]],
        }, URL)
        assert any("expired" in f["type"] for f in findings)

    def test_short_hsts_warns(self):
        from tblue.scanner.tls_certificate_deep import _check_hsts_header
        findings = _check_hsts_header({"strict-transport-security": "max-age=3600"}, URL)
        assert any("hsts" in f["type"] for f in findings)

    def test_long_hsts_passes(self):
        from tblue.scanner.tls_certificate_deep import _check_hsts_header
        findings = _check_hsts_header({"strict-transport-security": "max-age=31536000; includeSubDomains"}, URL)
        assert findings == []

    def test_result_structure(self):
        s = self._scanner()
        results = s.scan(HTTP_URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
