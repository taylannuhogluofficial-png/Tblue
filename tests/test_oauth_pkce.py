"""Tests for OAuth PKCE and Authorization Code Security scanner."""
import json
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestOAuthPKCEScanner:
    def _scanner(self):
        from tblue.scanner.oauth_pkce import OAuthPKCEScanner
        return OAuthPKCEScanner(MagicMock())

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.url = URL
        h = headers or {}
        r.headers.get = lambda k, d="": h.get(k.lower(), d)
        r.headers.items = lambda: h.items()
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_oauth_endpoints_passes(self):
        """Site without OAuth endpoints → PASS."""
        s = self._scanner()
        not_found = self._resp("<html>404</html>", 404)
        with patch.object(s.http, "get", return_value=not_found):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_implicit_flow_in_js_warns(self):
        """response_type=token in page JS → WARN."""
        s = self._scanner()
        body = '<script>var url = "/oauth/auth?response_type=token&client_id=app";</script>'
        not_found = self._resp("<html>404</html>", 404)

        def side(url):
            if url == URL:
                return self._resp(body)
            return not_found

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("implicit" in r["type"].lower() for r in warns)

    def test_client_secret_in_js_fails(self):
        """client_secret hardcoded in JS → FAIL."""
        s = self._scanner()
        body = '<script>const client_secret = "supersecretvalue123";</script>'
        not_found = self._resp("<html>404</html>", 404)

        def side(url):
            if url == URL:
                return self._resp(body)
            return not_found

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("client-secret" in r["type"].lower() for r in fails)

    def test_open_redirect_uri_fails(self):
        """Auth endpoint redirects to attacker's redirect_uri → FAIL."""
        s = self._scanner()

        oidc_doc = json.dumps({
            "authorization_endpoint": "https://example.com/oauth/authorize",
        })

        def side(url):
            if "openid-configuration" in url:
                return self._resp(oidc_doc)
            if "evil-tbl9z7x.com" in url:
                return self._resp("", 302, {"location": "https://evil-tbl9z7x.com/steal?code=abc"})
            if "oauth/authorize" in url:
                return self._resp("", 302, {"location": "https://example.com/callback?code=xyz"})
            return self._resp("<html></html>")

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("redirect" in r["type"].lower() for r in fails)

    def test_pkce_not_used_in_js_warns(self):
        """Auth endpoint exists but PKCE not detected in JS → WARN."""
        s = self._scanner()
        oidc_doc = json.dumps({
            "authorization_endpoint": "https://example.com/oauth/authorize",
        })

        def side(url):
            if "openid-configuration" in url:
                return self._resp(oidc_doc)
            if "oauth/authorize" in url:
                return self._resp("", 200)
            return self._resp("<html></html>")

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("pkce" in r["type"].lower() for r in warns)

    def test_pkce_used_passes_check(self):
        """Auth endpoint exists and PKCE detected in JS → no PKCE warning."""
        s = self._scanner()
        oidc_doc = json.dumps({
            "authorization_endpoint": "https://example.com/oauth/authorize",
        })
        body_with_pkce = '<script>params.code_challenge = generateCodeChallenge(verifier);</script>'

        def side(url):
            if "openid-configuration" in url:
                return self._resp(oidc_doc)
            if "oauth/authorize" in url:
                return self._resp("", 200)
            if url == URL:
                return self._resp(body_with_pkce)
            return self._resp("<html>404</html>", 404)

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        # Should not warn about PKCE not being used
        pkce_warns = [r for r in results if r["status"] == "WARN" and "pkce" in r.get("type", "").lower()]
        assert not pkce_warns

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>404</html>", 404)):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_implicit_flow(self):
        from tblue.scanner.oauth_pkce import _check_implicit_flow_in_page
        body = 'var url = authBase + "?response_type=token&client_id=" + cid;'
        finding = _check_implicit_flow_in_page(body)
        assert finding is not None
        assert finding["type"] == "oauth-implicit-flow"

    def test_no_implicit_flow(self):
        from tblue.scanner.oauth_pkce import _check_implicit_flow_in_page
        body = 'var url = authBase + "?response_type=code&code_challenge=" + cc;'
        finding = _check_implicit_flow_in_page(body)
        assert finding is None

    def test_client_secret_detection(self):
        from tblue.scanner.oauth_pkce import _check_client_secret_in_js
        body = 'const client_secret = "ABCDEFGHIJK12345";'
        finding = _check_client_secret_in_js(body)
        assert finding is not None
        assert finding["severity"] == "FAIL"

    def test_pkce_usage_detection(self):
        from tblue.scanner.oauth_pkce import _check_pkce_usage_in_js
        body = "params.code_challenge = base64urlEncode(hash);"
        assert _check_pkce_usage_in_js(body)

    def test_no_pkce_not_detected(self):
        from tblue.scanner.oauth_pkce import _check_pkce_usage_in_js
        body = "var response_type = 'code'; var state = generateState();"
        assert not _check_pkce_usage_in_js(body)
