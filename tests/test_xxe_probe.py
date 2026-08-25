"""Tests for XXE Passive scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestXXEProbeScanner:
    def _scanner(self):
        from tblue.scanner.xxe_probe import XXEProbeScanner
        return XXEProbeScanner(MagicMock())

    def _resp(self, body="OK", status=200, headers=None):
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

    def test_clean_html_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>OK</html>")):
            with patch.object(s.http, "post", return_value=self._resp("<error>not xml</error>", 400)):
                results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_external_entity_in_xml_fails(self):
        from tblue.scanner.xxe_probe import _check_xml_response_for_xxe
        body = '<?xml version="1.0"?><!ENTITY foo SYSTEM "file:///etc/passwd"><root/>'
        findings = _check_xml_response_for_xxe(body, "application/xml", URL)
        assert any("external_entity" in f["type"] for f in findings)

    def test_dtd_only_warns(self):
        from tblue.scanner.xxe_probe import _check_xml_response_for_xxe
        body = '<?xml version="1.0"?><!DOCTYPE root PUBLIC "-//W3C//DTD..." "http://example.com/dtd"><root/>'
        findings = _check_xml_response_for_xxe(body, "application/xml", URL)
        assert any("dtd" in f["type"] for f in findings)

    def test_entity_reflected_fails(self):
        from tblue.scanner.xxe_probe import _check_xml_endpoint_accepts_dtd
        http = MagicMock()
        r = MagicMock()
        r.status_code = 200
        r.text = "<response>probe</response>"
        http.post.return_value = r
        findings = _check_xml_endpoint_accepts_dtd(http, URL)
        assert any("reflected" in f["type"] for f in findings)

    def test_clean_xml_passes(self):
        from tblue.scanner.xxe_probe import _check_xml_response_for_xxe
        findings = _check_xml_response_for_xxe("<root><item>hello</item></root>", "application/xml", URL)
        assert findings == []

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            with patch.object(s.http, "post", return_value=self._resp("error", 400)):
                results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
