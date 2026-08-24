"""Tests for StorageBucketSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.storage_bucket_security import StorageBucketSecurityScanner


def _scanner():
    s = StorageBucketSecurityScanner.__new__(StorageBucketSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestSensitiveDataStored:
    def test_credentials_stored_fails(self):
        s = _scanner()
        body = "const bucket = await navigator.storageBuckets.open('cache')\nconst store = await bucket.indexedDB.open('db')\nstore.setItem('auth', token)"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "storage_bucket_sensitive_data_stored" in types


class TestNameFromParam:
    def test_bucket_name_from_url_param_fails(self):
        s = _scanner()
        body = "navigator.storageBuckets.open(searchParams.get('bucket'))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "storage_bucket_name_from_url_param" in types


class TestKeysExfil:
    def test_bucket_keys_exfiltrated_warns(self):
        s = _scanner()
        body = "const keys = await navigator.storageBuckets.keys()\nsendBeacon('/collect', JSON.stringify(keys))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "storage_bucket_keys_exfiltrated" in types


class TestNotUsed:
    def test_no_storage_bucket_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "storage_bucket_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
