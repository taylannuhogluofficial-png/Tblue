"""Tests for XML Security Passive scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestXMLSecurityPassiveScanner:
    def _scanner(self):
        from tblue.scanner.xml_security_passive import XMLSecurityPassiveScanner
        return XMLSecurityPassiveScanner(MagicMock())

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {"content-type": "text/html"}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_page_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>OK</html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_dtd_in_xml_response_warns(self):
        s = self._scanner()
        body = '<?xml version="1.0"?><!DOCTYPE root PUBLIC "-//W3C//DTD HTML 4.01//EN"><root/>'
        headers = {"content-type": "application/xml"}
        with patch.object(s.http, "get", return_value=self._resp(body, 200, headers)):
            results = s.scan(URL)
        found = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("dtd" in r["type"] for r in found)

    def test_entity_with_system_fails(self):
        s = self._scanner()
        body = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY foo SYSTEM "file:///etc/passwd">]><x/>'
        headers = {"content-type": "application/xml"}
        with patch.object(s.http, "get", return_value=self._resp(body, 200, headers)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("entity" in r["type"] for r in fails)

    def test_soap_response_warns(self):
        s = self._scanner()
        body = '<SOAP-ENV:Envelope xmlns:SOAP-ENV="..."><SOAP-ENV:Body><foo/></SOAP-ENV:Body></SOAP-ENV:Envelope>'
        headers = {"content-type": "application/soap+xml"}
        with patch.object(s.http, "get", return_value=self._resp(body, 200, headers)):
            results = s.scan(URL)
        found = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("soap" in r["type"] for r in found)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_xml_dtd(self):
        from tblue.scanner.xml_security_passive import _check_xml_response
        body = '<?xml version="1.0"?><!DOCTYPE root PUBLIC "-//foo//bar//EN"><root/>'
        findings = _check_xml_response(body, "application/xml", URL)
        assert any("dtd" in f["type"] for f in findings)

    def test_check_xml_clean(self):
        from tblue.scanner.xml_security_passive import _check_xml_response
        assert _check_xml_response("<root><item>test</item></root>", "application/xml", URL) == []

    def test_external_entity(self):
        from tblue.scanner.xml_security_passive import _check_xml_response
        body = '<!ENTITY foo SYSTEM "file:///etc/passwd">'
        findings = _check_xml_response(body, "text/xml", URL)
        assert any("entity" in f["type"] for f in findings)
