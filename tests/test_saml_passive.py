"""Tests for SAML Passive scanner."""
from unittest.mock import MagicMock, patch
URL = "https://example.com"

class TestSAMLPassiveScanner:
    def _scanner(self):
        from tblue.scanner.saml_passive import SAMLPassiveScanner
        return SAMLPassiveScanner(MagicMock())
    def _resp(self, body="OK", status=200, headers=None):
        r = MagicMock(); r.text = body; r.status_code = status; r.headers = headers or {}; return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None): results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_page_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>Welcome</html>", 404)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_saml_response_in_form_warns(self):
        from tblue.scanner.saml_passive import _check_saml_in_page
        body = '<form action="/acs"><input name="SAMLResponse" value="abc"><input name="RelayState" value="xyz"></form>'
        findings = _check_saml_in_page(body, URL)
        assert any("saml_response" in f["type"] for f in findings)

    def test_saml_endpoint_exposed_warns(self):
        from tblue.scanner.saml_passive import _probe_saml_endpoints
        http = MagicMock()
        r = MagicMock(); r.status_code = 302; r.text = "Redirect to IdP"
        http.get.return_value = r
        findings = _probe_saml_endpoints(http, "https://example.com")
        assert any("endpoint" in f["type"] for f in findings)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>clean</html>", 404)):
            results = s.scan(URL)
        for r in results: assert r["status"] in ("PASS", "WARN", "FAIL")
