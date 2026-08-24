"""Tests for Supply Chain Lockfile Exposure scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestSupplyChainLockfileScanner:
    def _scanner(self):
        from tblue.scanner.supply_chain_lockfile import SupplyChainLockfileScanner
        return SupplyChainLockfileScanner(MagicMock())

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {}
        r.url = URL
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_lockfiles_passes(self):
        """All paths return 404 → PASS."""
        s = self._scanner()
        not_found = self._resp("<html>404</html>", status=404)
        with patch.object(s.http, "get", return_value=not_found):
            results = s.scan(URL)
        assert all(r["status"] == "PASS" for r in results)

    def test_npm_lockfile_exposed_fails(self):
        """package-lock.json accessible → FAIL."""
        s = self._scanner()
        npm_lock = self._resp(
            '{"lockfileVersion":3,"name":"myapp","packages":{"node_modules/express":{"version":"4.18.0"}}}',
            200
        )
        root_resp = self._resp("<html></html>")

        def get_side(url):
            if "package-lock.json" in url:
                return npm_lock
            return self._resp("<html></html>", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails
        assert any("npm" in r["type"].lower() or "lockfile" in r["type"].lower() for r in fails)

    def test_yarn_lockfile_exposed_fails(self):
        """yarn.lock accessible → FAIL."""
        s = self._scanner()
        yarn_lock = self._resp(
            "# yarn lockfile v1\n\nlodash@^4.0.0:\n  version \"4.17.21\"\n  resolved \"https://registry.yarnpkg.com/lodash\"\n",
            200
        )

        def get_side(url):
            if "yarn.lock" in url:
                return yarn_lock
            return self._resp("<html></html>", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails
        assert any("yarn" in r["type"].lower() for r in fails)

    def test_poetry_lockfile_exposed_fails(self):
        """poetry.lock accessible → FAIL."""
        s = self._scanner()
        poetry_lock = self._resp(
            "[[package]]\nname = \"requests\"\nversion = \"2.28.0\"\n",
            200
        )

        def get_side(url):
            if "poetry.lock" in url:
                return poetry_lock
            return self._resp("<html></html>", 404)

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("poetry" in r["type"].lower() for r in fails)

    def test_html_response_not_detected_as_lockfile(self):
        """A 200 HTML response at package-lock.json path is not a lockfile."""
        s = self._scanner()
        html_resp = self._resp("<html><body>Not Found</body></html>", 200)

        def get_side(url):
            return html_resp

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert not fails, "HTML response should not be detected as lockfile"

    def test_result_structure(self):
        s = self._scanner()
        not_found = self._resp("<html></html>", 404)
        with patch.object(s.http, "get", return_value=not_found):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_is_real_npm_lockfile(self):
        from tblue.scanner.supply_chain_lockfile import _is_real_lockfile
        body = '{"lockfileVersion":3,"name":"test","packages":{}}'
        assert _is_real_lockfile(body, "npm")

    def test_is_not_real_lockfile_if_html(self):
        from tblue.scanner.supply_chain_lockfile import _is_real_lockfile
        body = "<html><body>Not found</body></html>"
        assert not _is_real_lockfile(body, "pip")

    def test_is_real_yarn_lockfile(self):
        from tblue.scanner.supply_chain_lockfile import _is_real_lockfile
        body = "# yarn lockfile v1\n\nexpress@^4:\n  version \"4.18.0\"\n"
        assert _is_real_lockfile(body, "yarn")

    def test_count_packages_npm(self):
        from tblue.scanner.supply_chain_lockfile import _count_packages
        body = (
            '{"packages":{"node_modules/express":{},"node_modules/lodash":{},'
            '"node_modules/react":{},"node_modules/react-dom":{}}}'
        )
        count = _count_packages(body, "npm")
        assert count == 4
