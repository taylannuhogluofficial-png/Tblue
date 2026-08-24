"""Tests for PackageManifestExposureScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.package_manifest_exposure import PackageManifestExposureScanner

URL = "https://example.com"


class TestPackageManifestExposure(unittest.TestCase):
    def _make(self):
        s = PackageManifestExposureScanner.__new__(PackageManifestExposureScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = {}
        return r

    # ── No manifest files ─────────────────────────────────────────────────────

    def test_no_manifest_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp("", status=404)
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── package.json exposed ──────────────────────────────────────────────────

    def test_package_json_exposed_warns(self):
        pkg = '{"name": "myapp", "version": "1.0.0", "dependencies": {"express": "^4.18.0", "lodash": "^4.17.21"}}'
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if u.endswith("package.json"):
                    return self._resp(pkg)
                return self._resp("", status=404)
            m.get.side_effect = side_effect
            results = s.scan(URL)
        warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("package" in r["type"].lower() or "manifest" in r["type"].lower() for r in warns_or_fails))

    # ── .npmrc with auth token fails ──────────────────────────────────────────

    def test_npmrc_with_auth_token_fails(self):
        npmrc = "registry=https://registry.npmjs.org/\n//registry.npmjs.org/:_authToken=npm_abc123def456xyz789"
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if ".npmrc" in u:
                    return self._resp(npmrc)
                return self._resp("", status=404)
            m.get.side_effect = side_effect
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("token" in r["type"].lower() or "auth" in r["type"].lower() or "npmrc" in r["type"].lower() for r in fails))

    # ── requirements.txt exposed ──────────────────────────────────────────────

    def test_requirements_txt_exposed_warns(self):
        reqs = "Django==4.2.3\nrequests==2.31.0\ncryptography==41.0.3"
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if "requirements.txt" in u:
                    return self._resp(reqs)
                return self._resp("", status=404)
            m.get.side_effect = side_effect
            results = s.scan(URL)
        warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(len(warns_or_fails) > 0)

    # ── composer.json exposed ─────────────────────────────────────────────────

    def test_composer_json_exposed_warns(self):
        composer = '{"name": "myapp/api", "require": {"laravel/framework": "^10.0"}}'
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if "composer.json" in u:
                    return self._resp(composer)
                return self._resp("", status=404)
            m.get.side_effect = side_effect
            results = s.scan(URL)
        warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(len(warns_or_fails) > 0)

    # ── Empty body (soft 404) not flagged ─────────────────────────────────────

    def test_empty_body_soft_404_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            def side_effect(u, **kw):
                if "package.json" in u:
                    return self._resp("", status=200)  # empty body = soft 404
                return self._resp("", status=404)
            m.get.side_effect = side_effect
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
