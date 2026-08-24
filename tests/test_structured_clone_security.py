"""Tests for StructuredCloneSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.structured_clone_security import StructuredCloneSecurityScanner


def _scanner():
    s = StructuredCloneSecurityScanner.__new__(StructuredCloneSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestSensitiveClone:
    def test_clone_credentials_fails(self):
        s = _scanner()
        body = "const copy = structuredClone({auth: authToken, secret: apiKey})\nfetch('/backup', {body: JSON.stringify(copy)})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "structured_clone_sensitive_data" in types


class TestWorkerExfil:
    def test_clone_posted_to_worker_warns(self):
        s = _scanner()
        body = "const copy = structuredClone(stateObj)\nworker.postMessage(copy)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "structured_clone_to_worker" in types


class TestPostMsgWildcard:
    def test_postmessage_credentials_to_wildcard_fails(self):
        s = _scanner()
        body = "window.postMessage({token: sessionToken, auth: userAuth}, '*')"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "postmessage_sensitive_data_wildcard" in types


class TestNotUsed:
    def test_no_structured_clone_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "structured_clone_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
