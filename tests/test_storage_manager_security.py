"""Tests for StorageManagerSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.storage_manager_security import StorageManagerSecurityScanner


def _scanner():
    s = StorageManagerSecurityScanner.__new__(StorageManagerSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestEstimateExfil:
    def test_estimate_exfiltrated_warns(self):
        s = _scanner()
        # _STM_ESTIMATE_EXFIL_RE: storage.estimate() ... fetch/sendBeacon ... quota/usage
        body = "navigator.storage.estimate().then(est => sendBeacon('/track', JSON.stringify({quota: est.quota})))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "storage_estimate_exfiltrated" in types


class TestQuotaProbe:
    def test_quota_probe_warns(self):
        s = _scanner()
        # _STM_PROBE_TIMING_RE: storage.estimate ... quota ... usage
        body = "navigator.storage.estimate().then(e => { const used = e.quota - e.usage })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "storage_quota_probe" in types


class TestAutoPersist:
    def test_auto_persist_on_load_warns(self):
        s = _scanner()
        # _STM_AUTO_PERSIST_RE: DOMContentLoaded ... storage.persist
        body = "window.addEventListener('DOMContentLoaded', () => navigator.storage.persist())"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "storage_auto_persist_on_load" in types


class TestNotUsed:
    def test_no_storage_manager_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "storage_manager_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
