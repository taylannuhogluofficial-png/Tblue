"""Tests for BackgroundFetchSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.background_fetch_security import BackgroundFetchSecurityScanner


def _scanner():
    s = BackgroundFetchSecurityScanner.__new__(BackgroundFetchSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestURLFromParam:
    def test_fetch_url_from_param_fails(self):
        s = _scanner()
        body = "registration.backgroundFetch.fetch('job', searchParams.get('endpoint'))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "background_fetch_url_from_param" in types


class TestSensitiveUpload:
    def test_sensitive_credential_upload_fails(self):
        s = _scanner()
        body = "const token = localStorage.getItem('auth_token')\nregistration.backgroundFetch.fetch('upload', '/api/sync', {body: token})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "background_fetch_sensitive_upload" in types


class TestCredentialExfil:
    def test_auth_post_via_background_fails(self):
        s = _scanner()
        body = "registration.backgroundFetch.fetch('sync', new Request('/collect', {method: 'POST', body: JSON.stringify({auth: credentials})}))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "background_fetch_credential_exfil" in types


class TestNotUsed:
    def test_no_background_fetch_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "background_fetch_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
