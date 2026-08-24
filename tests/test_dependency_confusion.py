"""Tests for Dependency Confusion scanner."""
from unittest.mock import MagicMock, patch

URL = "https://example.com"


class TestDependencyConfusionScanner:
    def _scanner(self):
        from tblue.scanner.dependency_confusion import DependencyConfusionScanner
        return DependencyConfusionScanner(MagicMock())

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

    def test_clean_page_passes(self):
        s = self._scanner()
        # Manifest probe paths return 404; homepage returns clean HTML
        def get_side(url, **kw):
            if url == URL:
                return self._resp("<html>no packages</html>")
            return self._resp("Not Found", 404)
        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_internal_scoped_package_fails(self):
        from tblue.scanner.dependency_confusion import _check_packages_for_confusion
        findings = _check_packages_for_confusion(["@internal/auth-lib", "@corp/utils"], URL)
        assert any("internal" in f["type"] for f in findings)
        assert any(f["status"] == "FAIL" for f in findings)

    def test_external_scoped_package_warns(self):
        from tblue.scanner.dependency_confusion import _check_packages_for_confusion
        findings = _check_packages_for_confusion(["@babel/core", "@vue/cli"], URL)
        assert any("scoped" in f["type"] for f in findings)

    def test_no_packages_passes(self):
        from tblue.scanner.dependency_confusion import _check_packages_for_confusion
        findings = _check_packages_for_confusion([], URL)
        assert findings == []

    def test_extract_from_import(self):
        from tblue.scanner.dependency_confusion import _extract_scoped_packages
        body = "import something from '@internal/auth-module';"
        pkgs = _extract_scoped_packages(body)
        assert "@internal/auth-module" in pkgs

    def test_extract_from_require(self):
        from tblue.scanner.dependency_confusion import _extract_scoped_packages
        body = "const x = require('@corp/shared-utils');"
        pkgs = _extract_scoped_packages(body)
        assert "@corp/shared-utils" in pkgs

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>clean</html>")):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
