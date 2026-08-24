"""Tests for DNS Rebinding Passive scanner."""
from unittest.mock import MagicMock, patch
URL = "https://example.com"

class TestDNSRebindingPassiveScanner:
    def _scanner(self):
        from tblue.scanner.dns_rebinding_passive import DNSRebindingPassiveScanner
        return DNSRebindingPassiveScanner(MagicMock())
    def _resp(self, body="OK", status=200, headers=None):
        r = MagicMock(); r.text = body; r.status_code = status; r.headers = headers or {}; return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None): results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_private_ip_in_body_warns(self):
        from tblue.scanner.dns_rebinding_passive import _check_private_ip_in_response
        findings = _check_private_ip_in_response("Server at 192.168.1.100:8080", {}, URL)
        assert any("private_ip" in f["type"] for f in findings)

    def test_localhost_reference_warns(self):
        from tblue.scanner.dns_rebinding_passive import _check_private_ip_in_response
        findings = _check_private_ip_in_response("Connect to localhost:3000", {}, URL)
        assert any("localhost" in f["type"] for f in findings)

    def test_clean_response_passes(self):
        from tblue.scanner.dns_rebinding_passive import _check_private_ip_in_response
        findings = _check_private_ip_in_response("<html>Welcome to our public site</html>", {}, URL)
        assert findings == []

    def test_host_not_validated_warns(self):
        from tblue.scanner.dns_rebinding_passive import _check_host_validation
        http = MagicMock(); r = MagicMock(); r.status_code = 200; r.text = "OK"
        http.get.return_value = r
        findings = _check_host_validation(http, URL)
        assert any("not_validated" in f["type"] for f in findings)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>clean</html>")):
            results = s.scan(URL)
        for r in results: assert r["status"] in ("PASS", "WARN", "FAIL")
