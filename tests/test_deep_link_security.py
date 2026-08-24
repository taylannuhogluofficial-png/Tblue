"""Tests for Deep Link Security scanner."""
from unittest.mock import MagicMock, patch
import pytest

URL = "https://example.com"
URL_HTTP = "http://example.com"


class TestDeepLinkSecurityScanner:
    def _scanner(self):
        from tblue.scanner.deep_link_security import DeepLinkSecurityScanner
        return DeepLinkSecurityScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        return r

    def test_no_aasa_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(status=404)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_aasa_wildcard_path_warns(self):
        s = self._scanner()
        import json
        aasa_body = json.dumps({
            "applinks": {
                "apps": [],
                "details": [{"appID": "TEAM.com.example.app", "paths": ["*"]}]
            }
        })

        def get_side(url, **kwargs):
            if "apple-app-site-association" in url:
                return self._resp(aasa_body)
            return self._resp(status=404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("wildcard" in r["type"].lower() or "aasa" in r["type"].lower() for r in warns)

    def test_aasa_http_warns(self):
        s = self._scanner()
        import json
        aasa_body = json.dumps({"applinks": {"apps": [], "details": []}})

        def get_side(url, **kwargs):
            if "apple-app-site-association" in url:
                return self._resp(aasa_body)
            return self._resp(status=404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL_HTTP)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("http" in r["type"].lower() or "aasa" in r["type"].lower() for r in warns)

    def test_assetlinks_empty_warns(self):
        s = self._scanner()

        def get_side(url, **kwargs):
            if "assetlinks" in url:
                return self._resp("[]")
            return self._resp(status=404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("assetlinks" in r["type"].lower() for r in warns)

    def test_custom_scheme_in_page_warns(self):
        s = self._scanner()
        body = '<a href="myapp://open/dashboard">Open in app</a>'
        with patch.object(s.http, "get", return_value=self._resp(body, 404)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("scheme" in r["type"].lower() or "deep" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(status=404)):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_check_custom_schemes(self):
        from tblue.scanner.deep_link_security import _check_custom_schemes
        body = '<a href="myapp://open/page">Open</a>'
        findings = _check_custom_schemes(body, URL)
        assert any("myapp" in f["type"].lower() for f in findings)

    def test_check_custom_schemes_standard_ok(self):
        from tblue.scanner.deep_link_security import _check_custom_schemes
        body = '<a href="https://example.com">Visit</a>'
        findings = _check_custom_schemes(body, URL)
        assert findings == []
