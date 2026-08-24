"""Tests for Path Parameter Pollution scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestPathParameterPollutionScanner:
    def _scanner(self):
        from tblue.scanner.path_parameter_pollution import PathParameterPollutionScanner
        return PathParameterPollutionScanner(MagicMock())

    def _resp(self, status=200, body="<html></html>"):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.url = URL
        r.headers = {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_bypass_passes(self):
        """All paths return consistent status → PASS."""
        s = self._scanner()
        normal = self._resp(200)
        with patch.object(s.http, "get", return_value=normal):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_matrix_param_bypasses_403_fails(self):
        """Clean path returns 403, matrix param path returns 200 → FAIL."""
        s = self._scanner()

        def side(url):
            if ";admin=true" in url or ";debug=1" in url or ";role=admin" in url:
                return self._resp(200)  # Bypassed!
            if "/api/users" in url or "/api/v1/users" in url:
                return self._resp(403)  # Blocked
            return self._resp(200)

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("matrix" in r["type"].lower() for r in fails)

    def test_no_matrix_bypass_on_200_paths_passes(self):
        """Path returns 200 normally AND with matrix param → no bypass."""
        s = self._scanner()
        normal = self._resp(200)
        with patch.object(s.http, "get", return_value=normal):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert not fails

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_status_changed_significantly_403_to_200(self):
        from tblue.scanner.path_parameter_pollution import _status_changed_significantly
        assert _status_changed_significantly(403, 200)

    def test_status_changed_significantly_401_to_200(self):
        from tblue.scanner.path_parameter_pollution import _status_changed_significantly
        assert _status_changed_significantly(401, 200)

    def test_status_not_changed_significantly(self):
        from tblue.scanner.path_parameter_pollution import _status_changed_significantly
        assert not _status_changed_significantly(200, 200)
        assert not _status_changed_significantly(200, 404)
        assert not _status_changed_significantly(403, 403)
