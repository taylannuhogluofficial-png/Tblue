"""Tests for TrustedTypesCspScanner."""
import pytest
from unittest.mock import MagicMock
from tblue.scanner.trusted_types_csp import TrustedTypesCspScanner


def _scanner():
    s = TrustedTypesCspScanner.__new__(TrustedTypesCspScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestTrustedTypesMissing:
    def test_dom_sink_no_trusted_types_warns(self):
        s = _scanner()
        body = '<div id="content"></div><script>element.innerHTML = userInput;</script>'
        s.http.get.return_value = _resp(200, body, {
            "content-security-policy": "default-src 'self'",
        })
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "trusted_types_missing_with_dom_sinks" in types

    def test_no_csp_no_sinks_info(self):
        s = _scanner()
        body = "<html><body>Normal page, no DOM sinks</body></html>"
        s.http.get.return_value = _resp(200, body, {})
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "trusted_types_not_configured" in types


class TestTrustedTypesEnforced:
    def test_trusted_types_enforced_passes(self):
        s = _scanner()
        body = "<html><body>Trusted Types page</body></html>"
        s.http.get.return_value = _resp(200, body, {
            "content-security-policy": "default-src 'self'; require-trusted-types-for 'script'; trusted-types my-policy",
        })
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "trusted_types_enforced" in types
        assert all(r["status"] == "PASS" for r in results)


class TestTrustedTypesApiWithoutEnforcement:
    def test_api_used_without_csp_warns(self):
        s = _scanner()
        body = """
        const policy = trustedTypes.createPolicy('my-policy', {
            createHTML: input => input,
        });
        element.innerHTML = userInput;
        """
        s.http.get.return_value = _resp(200, body, {
            "content-security-policy": "default-src 'self'",
        })
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "trusted_types_api_no_enforcement" in types


class TestTrustedTypesNoAllowlist:
    def test_enforcement_without_allowlist_warns(self):
        s = _scanner()
        body = "<html><body>Page with enforcement</body></html>"
        s.http.get.return_value = _resp(200, body, {
            "content-security-policy": "default-src 'self'; require-trusted-types-for 'script'",
        })
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "trusted_types_no_allowlist" in types


class TestNoResponse:
    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
