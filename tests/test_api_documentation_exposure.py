"""Tests for APIDocumentationExposureScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.api_documentation_exposure import (
    APIDocumentationExposureScanner, _is_doc_response,
)

URL = "https://example.com"

_SWAGGER_BODY = '{"openapi": "3.0.0", "info": {"title": "API"}, "paths": {"/users": {}}}'
_SWAGGER_SENSITIVE = '{"openapi": "3.0.0", "paths": {"/admin": {}, "/internal/config": {}}}'
_REDOC_BODY = "<html><script>Redoc.init('/openapi.json')</script></html>"


class TestAPIDocumentationExposure:
    def _scanner(self):
        return APIDocumentationExposureScanner(MagicMock())

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

    def test_is_doc_response_swagger(self):
        doc_type, sensitive = _is_doc_response(_SWAGGER_BODY)
        assert doc_type == "Swagger/OpenAPI"

    def test_is_doc_response_swagger_sensitive(self):
        doc_type, sensitive = _is_doc_response(_SWAGGER_SENSITIVE)
        assert doc_type == "Swagger/OpenAPI"
        assert sensitive is True

    def test_is_doc_response_redoc(self):
        doc_type, _ = _is_doc_response(_REDOC_BODY)
        assert doc_type == "ReDoc"

    def test_is_doc_response_unknown(self):
        doc_type, _ = _is_doc_response("<html>Not found</html>")
        assert doc_type == ""

    def test_swagger_exposed_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", side_effect=[
            self._resp("<html>main</html>"),
            self._resp(_SWAGGER_BODY),
        ]):
            results = s.scan(URL)
        issues = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("doc" in r["type"].lower() for r in issues)

    def test_swagger_with_sensitive_endpoints_fails(self):
        s = self._scanner()
        with patch.object(s.http, "get", side_effect=[
            self._resp("<html>main</html>"),
            self._resp(_SWAGGER_SENSITIVE),
        ]):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert len(fails) > 0

    def test_no_docs_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("Not Found", 404)):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("", 404)):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")
