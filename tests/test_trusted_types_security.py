"""Tests for TrustedTypesSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.trusted_types_security import TrustedTypesSecurityScanner


def _scanner():
    s = TrustedTypesSecurityScanner.__new__(TrustedTypesSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestDefaultPolicyOverride:
    def test_default_policy_fails(self):
        s = _scanner()
        body = "trustedTypes.createPolicy('default', { createHTML: h => h })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "trusted_types_default_policy_override" in types


class TestHTMLPassthrough:
    def test_html_passthrough_fails(self):
        s = _scanner()
        # _TT_PASSTHROUGH_RE: createPolicy(...), {createHTML: s => s,
        body = "trustedTypes.createPolicy('myPol'), { createHTML: s => s, }"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "trusted_types_html_passthrough" in types


class TestSinkBypass:
    def test_innerhtml_from_url_param_warns(self):
        s = _scanner()
        # _TT_ANY_RE needs trustedTypes keyword; _TT_BYPASS_SINK_RE: innerHTML = ... searchParams
        body = "trustedTypes.createPolicy('safe', null)\nel.innerHTML = searchParams.get('html')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "trusted_types_sink_bypass" in types


class TestNotUsed:
    def test_no_trusted_types_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "trusted_types_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
