"""Tests for Feature Flag Exposure scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"


class TestFeatureFlagExposureScanner:
    def _scanner(self):
        from tblue.scanner.feature_flag_exposure import FeatureFlagExposureScanner
        return FeatureFlagExposureScanner(MagicMock())

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
        with patch.object(s.http, "get", return_value=self._resp('var x = "hello";')):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_launchdarkly_sdk_key_fails(self):
        s = self._scanner()
        body = 'const ldKey = "sdk-12345678-1234-1234-1234-123456789012";'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("launchdarkly" in r["type"].lower() or "sdk" in r["type"].lower() for r in fails)

    def test_unleash_api_token_fails(self):
        s = self._scanner()
        body = 'const unleash_api_token = "mysecrettoken123456789012345678";'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("unleash" in r["type"].lower() for r in fails)

    def test_growthbook_secret_fails(self):
        s = self._scanner()
        body = 'apiKey: "gb_secret_abcdef1234567890abcdef12345"'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("growthbook" in r["type"].lower() or "secret" in r["type"].lower() for r in fails)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_scan_for_launchdarkly_sdk(self):
        from tblue.scanner.feature_flag_exposure import _scan_for_keys
        body = 'key: "sdk-a1b2c3d4-e5f6-7890-abcd-ef1234567890"'
        findings = _scan_for_keys(body, URL)
        assert any("launchdarkly" in f["type"].lower() for f in findings)
        assert findings[0]["status"] == "FAIL"

    def test_scan_for_growthbook(self):
        from tblue.scanner.feature_flag_exposure import _scan_for_keys
        body = 'const key = "gb_secret_xxxxxxxxxxxxxxxxxxxxxxxxxxx";'
        findings = _scan_for_keys(body, URL)
        assert any("growthbook" in f["type"].lower() for f in findings)

    def test_scan_clean(self):
        from tblue.scanner.feature_flag_exposure import _scan_for_keys
        findings = _scan_for_keys("var x = 1; const y = 'hello';", URL)
        assert findings == []
