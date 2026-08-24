"""Tests for JavaScript Framework Detection scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestJSFrameworkDetectionScanner:
    def _scanner(self):
        from tblue.scanner.js_framework_detection import JSFrameworkDetectionScanner
        return JSFrameworkDetectionScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        r.url = URL
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_clean_page_passes(self):
        s = self._scanner()
        body = "<html><body><p>Hello World</p></body></html>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_old_jquery_warns(self):
        """jQuery 1.x → WARN vulnerable version."""
        s = self._scanner()
        body = '<script src="/jquery-1.11.3.min.js"></script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("jquery" in r["type"].lower() or "jQuery" in r["type"] for r in warns)

    def test_old_angular_warns(self):
        """AngularJS 1.x → WARN EOL."""
        s = self._scanner()
        body = '<script src="/angular@1.8.3/angular.min.js"></script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("angular" in r["type"].lower() or "Angular" in r["type"] for r in warns)

    def test_dev_build_warns(self):
        """React development build in production → WARN."""
        s = self._scanner()
        body = '<script src="/react.development.js"></script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("dev" in r["type"].lower() or "development" in r["type"].lower() for r in warns)

    def test_modern_jquery_passes(self):
        """jQuery 3.7.x → no vuln warning."""
        s = self._scanner()
        body = '<script src="/jquery-3.7.1.min.js"></script>'
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        # Should not flag 3.x as vulnerable
        vuln_warns = [r for r in results if r["status"] == "WARN"
                      and "framework-vuln" in r.get("type", "")]
        assert not vuln_warns

    def test_result_structure(self):
        s = self._scanner()
        body = "<html><body></body></html>"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_detect_frameworks_jquery(self):
        from tblue.scanner.js_framework_detection import _detect_frameworks
        body = '<script src="/jquery-3.6.0.min.js"></script>'
        detected = _detect_frameworks(body, ["/jquery-3.6.0.min.js"])
        names = [n for n, _ in detected]
        assert "jQuery" in names

    def test_detect_frameworks_react(self):
        from tblue.scanner.js_framework_detection import _detect_frameworks
        body = '<script src="/react.development.js"></script>'
        detected = _detect_frameworks(body, ["/react.development.js"])
        names = [n for n, _ in detected]
        assert "React" in names

    def test_check_vuln_version_old_jquery(self):
        from tblue.scanner.js_framework_detection import _check_vuln_version
        msg = _check_vuln_version("jQuery", "1.11.3")
        assert msg is not None

    def test_check_vuln_version_modern_jquery(self):
        from tblue.scanner.js_framework_detection import _check_vuln_version
        msg = _check_vuln_version("jQuery", "3.7.1")
        assert msg is None

    def test_detect_dev_builds(self):
        from tblue.scanner.js_framework_detection import _detect_dev_builds
        body = '<script src="/react.development.js"></script>'
        results = _detect_dev_builds(body)
        assert results
