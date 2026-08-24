"""Tests for PortalsSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.portals_security import PortalsSecurityScanner


def _scanner():
    s = PortalsSecurityScanner.__new__(PortalsSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestSrcFromURLParam:
    def test_portal_src_from_url_param_fails(self):
        s = _scanner()
        # _PORTAL_ANY_RE needs <portal or HTMLPortalElement; _PORTAL_SRC_URL_PARAM_RE: portal.src ... searchParams
        body = "<portal src='/default'></portal>\nportal.src = searchParams.get('page')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "portals_src_from_url_param" in types


class TestSensitivePage:
    def test_admin_page_embedded_warns(self):
        s = _scanner()
        body = '<portal src="/admin/dashboard"></portal>'
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "portals_sensitive_page_embedded" in types


class TestActivateWithSensitiveData:
    def test_activate_with_token_fails(self):
        s = _scanner()
        body = "portal.activate({data: {auth: sessionToken}})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "portals_sensitive_data_on_activate" in types


class TestNotUsed:
    def test_no_portals_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "portals_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
