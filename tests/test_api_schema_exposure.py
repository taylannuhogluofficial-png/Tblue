"""Tests for API Schema Exposure scanner."""
import json
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


class TestAPISchemaExposureScanner:
    def _scanner(self):
        from tblue.scanner.api_schema_exposure import APISchemaExposureScanner
        return APISchemaExposureScanner(MagicMock())

    def _resp(self, body="", status=200, ct="application/json"):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {"content-type": ct}
        r.url = URL
        return r

    def _openapi_resp(self, paths=None):
        data = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": paths or {
                "/users": {"get": {}},
                "/products": {"get": {}, "post": {}},
            },
        }
        return self._resp(json.dumps(data))

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_schemas_passes(self):
        """All paths return 404 → PASS."""
        s = self._scanner()
        not_found = self._resp("<html>404</html>", 404)
        with patch.object(s.http, "get", return_value=not_found):
            results = s.scan(URL)
        assert all(r["status"] == "PASS" for r in results)

    def test_openapi_json_exposed_warns(self):
        """/openapi.json with real content → WARN."""
        s = self._scanner()
        openapi = self._openapi_resp()

        def side(url):
            if "openapi.json" in url:
                return openapi
            return self._resp("<html></html>", 404)

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        non_pass = [r for r in results if r["status"] != "PASS"]
        assert non_pass
        assert any("openapi" in r["type"].lower() or "schema" in r["type"].lower() for r in non_pass)

    def test_swagger_json_exposed_warns(self):
        """/swagger.json exposed → WARN."""
        s = self._scanner()
        swagger = self._resp(json.dumps({
            "swagger": "2.0",
            "info": {"title": "API", "version": "1.0"},
            "paths": {"/health": {"get": {}}},
        }))

        def side(url):
            if "swagger.json" in url and "/api/swagger" not in url:
                return swagger
            return self._resp("<html>404</html>", 404)

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        assert any(r["status"] in ("WARN", "FAIL") for r in results)

    def test_html_response_not_detected(self):
        """HTML at schema path → not detected as schema."""
        s = self._scanner()
        html_resp = self._resp("<html><body>Not found</body></html>", 200)
        with patch.object(s.http, "get", return_value=html_resp):
            results = s.scan(URL)
        assert all(r["status"] == "PASS" for r in results)

    def test_credential_leak_in_schema_fails(self):
        """API key in schema body → FAIL."""
        s = self._scanner()
        schema_body = json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "API", "version": "1.0"},
            "paths": {},
        }) + ' "api_key": "ABCDEF1234567890"'

        def side(url):
            if "openapi.json" in url:
                r = self._resp(schema_body)
                return r
            return self._resp("<html></html>", 404)

        with patch.object(s.http, "get", side_effect=side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert fails

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html></html>", 404)):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_is_real_schema_openapi(self):
        from tblue.scanner.api_schema_exposure import _is_real_schema
        body = '{"openapi": "3.0.0", "info": {}, "paths": {}}'
        assert _is_real_schema(body, "/openapi.json")

    def test_is_real_schema_swagger(self):
        from tblue.scanner.api_schema_exposure import _is_real_schema
        body = '{"swagger": "2.0", "info": {}, "paths": {}}'
        assert _is_real_schema(body, "/swagger.json")

    def test_is_not_real_schema_html(self):
        from tblue.scanner.api_schema_exposure import _is_real_schema
        body = "<html><body>Not Found</body></html>"
        assert not _is_real_schema(body, "/openapi.json")

    def test_count_endpoints(self):
        from tblue.scanner.api_schema_exposure import _count_endpoints
        body = json.dumps({"paths": {"/a": {}, "/b": {}, "/c": {}}})
        assert _count_endpoints(body) == 3

    def test_check_auth_finds_bearer(self):
        from tblue.scanner.api_schema_exposure import _check_auth_in_schema
        body = 'Authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig"'
        result = _check_auth_in_schema(body)
        assert result is not None
