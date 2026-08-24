"""Tests for SharedWorkerSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.shared_worker_security import SharedWorkerSecurityScanner


def _scanner():
    s = SharedWorkerSecurityScanner.__new__(SharedWorkerSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestURLFromParam:
    def test_shared_worker_url_from_param_fails(self):
        s = _scanner()
        # _SW_URL_FROM_PARAM_RE: new SharedWorker(...searchParams...)
        body = "const w = new SharedWorker(searchParams.get('worker'))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "shared_worker_url_from_param" in types


class TestBroadcastSensitive:
    def test_broadcasts_sensitive_data_fails(self):
        s = _scanner()
        # _SW_BROADCAST_SENSITIVE_RE: ports...postMessage...token
        body = "self.onconnect = e => { ports.forEach(p => p.postMessage({token: sessionToken})) }"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "shared_worker_broadcasts_sensitive_data" in types


class TestSensitiveGlobal:
    def test_sensitive_global_state_warns(self):
        s = _scanner()
        # _SW_SENSITIVE_GLOBAL_RE: self.onconnect ... token
        body = "self.onconnect = function(e) { const tok = authToken\ne.ports[0].postMessage(tok) }"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "shared_worker_sensitive_global_state" in types


class TestNotUsed:
    def test_no_shared_worker_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "shared_worker_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
