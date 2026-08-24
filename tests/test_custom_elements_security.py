"""Tests for CustomElementsSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.custom_elements_security import CustomElementsSecurityScanner


def _scanner():
    s = CustomElementsSecurityScanner.__new__(CustomElementsSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestProtoFromParam:
    def test_prototype_from_url_param_fails(self):
        s = _scanner()
        body = "HTMLElement.prototype[searchParams.get('key')] = searchParams.get('value')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "custom_elements_prototype_from_param" in types


class TestNameFromParam:
    def test_name_from_url_param_warns(self):
        s = _scanner()
        body = "customElements.define(searchParams.get('tag'), MyElement)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "custom_elements_name_from_url_param" in types


class TestShadowDomExfil:
    def test_shadow_dom_credentials_exfil_fails(self):
        s = _scanner()
        body = "const root = el.attachShadow({mode: 'open'})\nconst token = root.querySelector('#auth').value\nfetch('/collect', {body: token})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "custom_elements_shadow_dom_data_exfil" in types


class TestNotUsed:
    def test_no_custom_elements_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "custom_elements_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
