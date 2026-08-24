"""Tests for OAuth Redirect URI Validation scanner."""
from unittest.mock import MagicMock, patch
URL = "https://example.com"

class TestOAuthRedirectURIValidationScanner:
    def _scanner(self):
        from tblue.scanner.oauth_redirect_uri_validation import OAuthRedirectURIValidationScanner
        return OAuthRedirectURIValidationScanner(MagicMock())
    def _resp(self, body="OK", status=200, headers=None):
        r = MagicMock(); r.text = body; r.status_code = status; r.headers = headers or {}; return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None): results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_missing_state_fails(self):
        from tblue.scanner.oauth_redirect_uri_validation import _check_oauth_links_in_page
        body = '<a href="/oauth/authorize?client_id=abc&response_type=code&redirect_uri=https://app.com/cb">Login</a>'
        findings = _check_oauth_links_in_page(body, URL)
        assert any("state" in f["type"] for f in findings)

    def test_with_state_passes(self):
        from tblue.scanner.oauth_redirect_uri_validation import _check_oauth_links_in_page
        body = '<a href="/oauth/authorize?client_id=abc&response_type=code&state=xyz123&redirect_uri=https://app.com/cb">Login</a>'
        findings = _check_oauth_links_in_page(body, URL)
        state_fails = [f for f in findings if "state" in f["type"]]
        assert not state_fails

    def test_open_redirect_via_oauth_fails(self):
        from tblue.scanner.oauth_redirect_uri_validation import _probe_redirect_uri_validation, _REDIRECT_URI_PROBE
        http = MagicMock()
        r = MagicMock(); r.status_code = 302; r.text = ""
        r.headers = {"location": f"{_REDIRECT_URI_PROBE}?code=abc"}
        http.get.return_value = r
        findings = _probe_redirect_uri_validation(http, "https://example.com")
        assert any("open_redirect" in f["type"] for f in findings)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>clean</html>")):
            results = s.scan(URL)
        for r in results: assert r["status"] in ("PASS", "WARN", "FAIL")
