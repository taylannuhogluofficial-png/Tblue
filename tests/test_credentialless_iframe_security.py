"""Tests for CredentiallessIframeSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.credentialless_iframe_security import CredentiallessIframeSecurityScanner


def _scanner():
    s = CredentiallessIframeSecurityScanner.__new__(CredentiallessIframeSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestStorageAccess:
    def test_storage_access_warns(self):
        s = _scanner()
        body = '<iframe src="/widget" credentialless></iframe>\n<script>iframeEl.contentDocument.localStorage.getItem("session")</script>'
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "credentialless_iframe_storage_access" in types


class TestPostMessageExfil:
    def test_postmessage_exfil_fails(self):
        s = _scanner()
        body = '<iframe credentialless src="/embed"></iframe>\n<script>frame.contentWindow.postMessage({token: authToken, auth: session}, "*")</script>'
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "credentialless_iframe_postmessage_exfil" in types


class TestFetchWithCredentials:
    def test_fetch_with_credentials_warns(self):
        s = _scanner()
        body = '<iframe credentialless src="/frame"></iframe>\n<script>fetch("/api", {credentials: "include", method: "GET"})</script>'
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "credentialless_iframe_fetch_with_credentials" in types


class TestNotUsed:
    def test_no_credentialless_iframe_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "credentialless_iframe_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
