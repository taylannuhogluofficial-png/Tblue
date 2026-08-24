"""Tests for DNS Rebinding Risk scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"
URL_HTTP = "http://example.com"


class TestDNSRebindingScanner:
    def _scanner(self):
        from tblue.scanner.dns_rebinding import DNSRebindingScanner
        return DNSRebindingScanner(MagicMock())

    def _resp(self, body="", status=200, headers=None):
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

    def test_accepts_arbitrary_host_warns(self):
        """Server returns 200 to evil Host header → WARN."""
        s = self._scanner()
        ok_resp = self._resp("<html>ok</html>", 200)

        with patch.object(s.http, "get", return_value=ok_resp):
            with patch("tblue.scanner.dns_rebinding._resolve_ips", return_value=[("IPv4", "93.184.216.34")]):
                with patch("tblue.scanner.dns_rebinding._get_dns_ttl", return_value=300):
                    results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("host" in r["type"].lower() or "arbitrary" in r["type"].lower() for r in warns)

    def test_private_ip_in_dns_warns(self):
        """Private IP in DNS records → WARN."""
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            with patch("tblue.scanner.dns_rebinding._resolve_ips",
                       return_value=[("IPv4", "192.168.1.100")]):
                with patch("tblue.scanner.dns_rebinding._get_dns_ttl", return_value=300):
                    results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("private" in r["type"].lower() or "ip" in r["type"].lower() for r in warns)

    def test_low_ttl_warns(self):
        """DNS TTL < 30 seconds → WARN."""
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(status=403)):
            with patch("tblue.scanner.dns_rebinding._resolve_ips",
                       return_value=[("IPv4", "93.184.216.34")]):
                with patch("tblue.scanner.dns_rebinding._get_dns_ttl", return_value=5):
                    results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("ttl" in r["type"].lower() for r in warns)

    def test_http_only_warns(self):
        """Plain HTTP target → WARN (no TLS protection)."""
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(status=403)):
            with patch("tblue.scanner.dns_rebinding._resolve_ips",
                       return_value=[("IPv4", "93.184.216.34")]):
                with patch("tblue.scanner.dns_rebinding._get_dns_ttl", return_value=300):
                    results = s.scan(URL_HTTP)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("http" in r["type"].lower() or "tls" in r["type"].lower() for r in warns)

    def test_no_risk_factors_passes(self):
        """No rebinding factors → PASS."""
        s = self._scanner()
        # Server returns 400 for evil Host (validates it), public IP, high TTL, HTTPS
        def get_side(url, headers=None, **kwargs):
            if (headers or {}).get("Host", "").startswith("evil"):
                return self._resp("", 400)
            return self._resp("", 200)

        with patch.object(s.http, "get", side_effect=get_side):
            with patch("tblue.scanner.dns_rebinding._resolve_ips",
                       return_value=[("IPv4", "93.184.216.34")]):
                with patch("tblue.scanner.dns_rebinding._get_dns_ttl", return_value=300):
                    results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(status=403)):
            with patch("tblue.scanner.dns_rebinding._resolve_ips", return_value=[]):
                with patch("tblue.scanner.dns_rebinding._get_dns_ttl", return_value=None):
                    results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_is_private_loopback(self):
        from tblue.scanner.dns_rebinding import _is_private
        assert _is_private("127.0.0.1") is True

    def test_is_private_rfc1918_10(self):
        from tblue.scanner.dns_rebinding import _is_private
        assert _is_private("10.0.0.1") is True

    def test_is_private_rfc1918_192(self):
        from tblue.scanner.dns_rebinding import _is_private
        assert _is_private("192.168.100.5") is True

    def test_is_private_rfc1918_172(self):
        from tblue.scanner.dns_rebinding import _is_private
        assert _is_private("172.16.0.1") is True
        assert _is_private("172.31.255.255") is True

    def test_is_not_private_public(self):
        from tblue.scanner.dns_rebinding import _is_private
        assert _is_private("93.184.216.34") is False

    def test_resolve_ips_failure(self):
        from tblue.scanner.dns_rebinding import _resolve_ips
        result = _resolve_ips("192.0.2.invalid.tbl9z7x.local")
        assert isinstance(result, list)  # graceful failure returns empty list
