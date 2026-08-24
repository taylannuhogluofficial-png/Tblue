"""Tests for DockerExposureScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.docker_exposure import DockerExposureScanner

URL = "https://example.com"


class TestDockerExposure(unittest.TestCase):
    def _make(self):
        s = DockerExposureScanner.__new__(DockerExposureScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = headers or {}
        return r

    def _not_found(self):
        return self._resp("Not Found", 404)

    # ── Docker API ────────────────────────────────────────────────────────────

    def test_docker_api_exposed_fails(self):
        body = '{"DockerRootDir":"/var/lib/docker","ServerVersion":"24.0.5","Containers":3}'

        def side(url, **kw):
            if "/v1.41/info" in url:
                return self._resp(body)
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("daemon" in r["type"].lower() or "api" in r["type"].lower() for r in fails))

    def test_no_docker_api_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._not_found()
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── Registry ──────────────────────────────────────────────────────────────

    def test_registry_unauthenticated_fails(self):
        def side(url, **kw):
            if "/v2/" in url and "_catalog" not in url:
                return self._resp(
                    '{"version":2}',
                    200,
                    {"Docker-Distribution-Api-Version": "registry/2.0"}
                )
            if "_catalog" in url:
                return self._resp('{"repositories":["app","db"]}', 200)
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("registry" in r["type"].lower() for r in fails))

    def test_registry_with_auth_warns(self):
        def side(url, **kw):
            if "/v2/" in url and "_catalog" not in url:
                return self._resp(
                    '{"errors":[{"code":"UNAUTHORIZED"}]}',
                    401,
                    {"Docker-Distribution-Api-Version": "registry/2.0"}
                )
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "WARN" for r in results))

    def test_registry_catalog_exposed_fails(self):
        def side(url, **kw):
            if "_catalog" in url:
                return self._resp('{"repositories":["myapp","mydb"]}', 200)
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("catalog" in r["type"].lower() for r in fails))

    # ── Container headers ─────────────────────────────────────────────────────

    def test_container_header_warns(self):
        def side(url, **kw):
            if url == "https://example.com":
                return self._resp("OK", 200, {"X-Powered-By": "portainer/2.19.0"})
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "WARN" for r in results))

    def test_no_container_headers_clean(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp("OK", 200, {"Server": "nginx"})
            results = s.scan(URL)
        # Should not flag normal headers
        warns = [r for r in results if "header" in r["type"].lower() and r["status"] == "WARN"]
        self.assertEqual(len(warns), 0)

    # ── Env leakage ───────────────────────────────────────────────────────────

    def test_dockerenv_accessible_fails(self):
        def side(url, **kw):
            if "/.dockerenv" in url:
                return self._resp("", 200)
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any(".dockerenv" in r["type"].lower() or "docker" in r["type"].lower() for r in fails))

    def test_proc_cgroup_exposed_fails(self):
        def side(url, **kw):
            if "/proc/1/cgroup" in url:
                return self._resp("12:cpuset:/docker/abc123def456\n", 200)
            return self._not_found()

        s = self._make()
        with patch.object(s, "http") as m:
            m.get.side_effect = side
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("cgroup" in r["type"].lower() or "docker" in r["type"].lower() for r in fails))

    # ── Clean page ────────────────────────────────────────────────────────────

    def test_clean_page_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._not_found()
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))
