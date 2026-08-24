"""Tests for TLS Protocol Version scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"
URL_HTTP = "http://example.com"


class TestTLSProtocolVersionScanner:
    def _scanner(self):
        from tblue.scanner.tls_protocol_version import TLSProtocolVersionScanner
        return TLSProtocolVersionScanner(MagicMock())

    def test_http_url_passes(self):
        """Non-HTTPS URL → PASS (skipped)."""
        s = self._scanner()
        results = s.scan(URL_HTTP)
        assert any(r["status"] == "PASS" for r in results)

    def test_tls10_accepted_fails(self):
        """Server accepts TLS 1.0 → FAIL."""
        s = self._scanner()
        with patch("tblue.scanner.tls_protocol_version._check_protocol",
                   return_value=[{
                       "type": "tls-protocol-tls10-accepted",
                       "severity": "FAIL",
                       "detail": "TLS 1.0 handshake succeeded."
                   }]):
            with patch("tblue.scanner.tls_protocol_version.socket"):
                with patch("tblue.scanner.tls_protocol_version.ssl") as mock_ssl:
                    mock_ssl.SSLContext.return_value.__enter__ = MagicMock()
                    mock_ssl.SSLContext.return_value.wrap_socket.side_effect = Exception("no conn")
                    results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("tls10" in r["type"].lower() for r in fails)

    def test_tls11_accepted_warns(self):
        """Server accepts TLS 1.1 → WARN."""
        s = self._scanner()
        with patch("tblue.scanner.tls_protocol_version._check_protocol",
                   return_value=[{
                       "type": "tls-protocol-tls11-accepted",
                       "severity": "WARN",
                       "detail": "TLS 1.1 handshake succeeded."
                   }]):
            with patch("tblue.scanner.tls_protocol_version.socket"):
                with patch("tblue.scanner.tls_protocol_version.ssl") as mock_ssl:
                    mock_ssl.SSLContext.return_value.__enter__ = MagicMock()
                    mock_ssl.SSLContext.return_value.wrap_socket.side_effect = Exception("no conn")
                    results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("tls11" in r["type"].lower() for r in warns)

    def test_no_issues_passes(self):
        """No deprecated protocols or weak ciphers → PASS."""
        s = self._scanner()
        with patch("tblue.scanner.tls_protocol_version._check_protocol", return_value=[]):
            with patch("tblue.scanner.tls_protocol_version.socket.create_connection",
                       side_effect=Exception("no conn")):
                results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch("tblue.scanner.tls_protocol_version._check_protocol", return_value=[]):
            with patch("tblue.scanner.tls_protocol_version.socket.create_connection",
                       side_effect=Exception("no conn")):
                results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_cipher_rc4(self):
        from tblue.scanner.tls_protocol_version import _check_cipher
        result = _check_cipher("ECDHE-RSA-RC4-SHA")
        assert result is not None
        assert result["severity"] == "FAIL"

    def test_check_cipher_3des(self):
        from tblue.scanner.tls_protocol_version import _check_cipher
        result = _check_cipher("ECDHE-RSA-DES-CBC3-SHA")
        assert result is not None
        assert result["severity"] == "WARN"

    def test_check_cipher_export(self):
        from tblue.scanner.tls_protocol_version import _check_cipher
        result = _check_cipher("EXP-RC4-MD5")
        assert result is not None
        assert result["severity"] == "FAIL"

    def test_check_cipher_null(self):
        from tblue.scanner.tls_protocol_version import _check_cipher
        result = _check_cipher("RSA-NULL-SHA256")
        assert result is not None
        assert result["severity"] == "FAIL"

    def test_check_cipher_good(self):
        from tblue.scanner.tls_protocol_version import _check_cipher
        result = _check_cipher("TLS_AES_256_GCM_SHA384")
        assert result is None

    def test_check_cipher_aes_gcm(self):
        from tblue.scanner.tls_protocol_version import _check_cipher
        result = _check_cipher("ECDHE-RSA-AES256-GCM-SHA384")
        assert result is None

    def test_tls_handshake_connection_failure(self):
        from tblue.scanner.tls_protocol_version import _tls_handshake
        import ssl
        result = _tls_handshake("192.0.2.1", 443,
                                ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
        assert result is None  # should gracefully return None on failure
