"""Tests for API Key in JS scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestAPIKeyInJSScanner:
    def _scanner(self):
        from tblue.scanner.api_key_in_js import APIKeyInJSScanner
        return APIKeyInJSScanner(MagicMock())

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

    def test_no_keys_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("var x = 1;")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_aws_key_fails(self):
        s = self._scanner()
        body = 'var key = "AKIAIOSFODNN7EXAMPLE";'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("aws" in r["type"] for r in fails)

    def test_gcp_key_warns(self):
        s = self._scanner()
        body = 'apiKey: "AIzaSyDx3xY9Mz8oQ2aRt7bVkJcLeN6pWsHgUi0"'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        assert any("gcp" in r["type"] for r in results)

    def test_stripe_secret_fails(self):
        s = self._scanner()
        body = 'stripeKey = "sk_live_abc123xyz456abc123xyz456ab"'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("stripe" in r["type"] for r in fails)

    def test_pem_private_key_fails(self):
        s = self._scanner()
        body = '-----BEGIN RSA PRIVATE KEY-----\nMIIEo...\n-----END RSA PRIVATE KEY-----'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("private" in r["type"] or "pem" in r["type"] for r in fails)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("var x = 1;")):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_scan_aws_key(self):
        from tblue.scanner.api_key_in_js import _scan_for_keys
        body = 'access_key = "AKIAIOSFODNN7EXAMPLE";'
        findings = _scan_for_keys(body, URL)
        assert any("aws" in f["type"] for f in findings)

    def test_scan_no_keys(self):
        from tblue.scanner.api_key_in_js import _scan_for_keys
        findings = _scan_for_keys("var hello = 'world';", URL)
        assert findings == []

    def test_scan_stripe(self):
        from tblue.scanner.api_key_in_js import _scan_for_keys
        body = 'key = "sk_live_abc123xyz456abc123xyz456ab"'
        findings = _scan_for_keys(body, URL)
        assert any("stripe" in f["type"] for f in findings)
