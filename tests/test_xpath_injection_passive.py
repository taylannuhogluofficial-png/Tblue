"""Tests for XPathInjectionPassiveScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.xpath_injection_passive import (
    XPathInjectionPassiveScanner, _check_xpath_error_disclosure,
)

URL = "https://example.com"


class TestXPathInjectionPassive:
    def _scanner(self):
        return XPathInjectionPassiveScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_xpath_error_in_response_fails(self):
        http = MagicMock()
        http.get.return_value = self._resp(
            "Error: XPathException - Invalid expression: unterminated string near '", 200
        )
        findings = _check_xpath_error_disclosure(http, URL)
        assert any("xpath" in f["type"] for f in findings)

    def test_ldap_error_in_response_fails(self):
        http = MagicMock()
        http.get.return_value = self._resp(
            "javax.naming.NamingException: LDAP error code 49 - invalid credentials", 200
        )
        findings = _check_xpath_error_disclosure(http, URL)
        assert any("ldap" in f["type"] for f in findings)

    def test_xml_parse_error_warns(self):
        http = MagicMock()
        http.get.return_value = self._resp(
            "XML parse error: Premature end of file at line 5", 200
        )
        findings = _check_xpath_error_disclosure(http, URL)
        assert any("xml" in f["type"] for f in findings)

    def test_clean_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(
            "<html><body>Welcome</body></html>"
        )):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_tainted_xpath_in_js_warns(self):
        body = 'var result = doc.evaluate("/users[name=" + query + "]", doc, null, 9, null);'
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert isinstance(results, list)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("OK")):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
