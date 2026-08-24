"""Extra branch coverage for tblue.scanner.api_surface."""

from unittest.mock import MagicMock, patch
from tblue.scanner.api_surface import APISurfaceScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return APISurfaceScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {"content-type": "application/json"}
    return r


def _404():
    return _resp(404, "Not Found", {"content-type": "text/html"})


MINIMAL_OPENAPI = """{
  "openapi": "3.0.0",
  "info": {"title": "Test API", "version": "1.0"},
  "paths": {
    "/users": {"get": {"summary": "List users"}, "post": {"summary": "Create user"}},
    "/admin": {"delete": {"summary": "Delete all users"}}
  }
}"""


def test_no_api_docs_returns_pass():
    """Covers the branch where no API documentation is found at any path."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_404()):
        results = s.scan(URL)
    assert all(r["status"] == "PASS" for r in results)


def test_openapi_spec_exposed_returns_result():
    """Covers the branch where a valid OpenAPI spec is found and analysed."""
    s = _scanner()

    def fake_get(url, **kw):
        if "/openapi.json" in url or "/swagger.json" in url:
            return _resp(200, MINIMAL_OPENAPI, {"content-type": "application/json"})
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert any(r["status"] in ("FAIL", "WARN", "PASS") for r in results)
    assert len(results) >= 1


def test_swagger_ui_html_page_flagged():
    """Covers the branch where HTML Swagger UI is detected (not JSON spec)."""
    s = _scanner()

    def fake_get(url, **kw):
        if "/swagger-ui.html" in url or "/swagger-ui/index.html" in url:
            return _resp(200, "<html><body>Swagger UI</body></html>",
                         {"content-type": "text/html"})
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert any(r["status"] in ("WARN", "FAIL") for r in results)


def test_unparseable_json_at_doc_path_warns():
    """Covers the branch where API doc path returns 200 but unparseable content."""
    s = _scanner()

    def fake_get(url, **kw):
        if "/api-docs" in url:
            return _resp(200, "this is not valid json or yaml {{{", {"content-type": "application/json"})
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_sensitive_schema_names_flagged():
    """Covers the branch where sensitive field names appear in the spec."""
    s = _scanner()
    spec_with_secrets = """{
  "openapi": "3.0.0",
  "info": {"title": "Sensitive API", "version": "1.0"},
  "components": {
    "schemas": {
      "LoginRequest": {
        "properties": {
          "password": {"type": "string"},
          "api_key": {"type": "string"},
          "secret": {"type": "string"}
        }
      }
    }
  },
  "paths": {"/login": {"post": {}}}
}"""

    def fake_get(url, **kw):
        if "/openapi.json" in url:
            return _resp(200, spec_with_secrets, {"content-type": "application/json"})
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert any(r["status"] in ("WARN", "FAIL") for r in results)


def test_all_results_have_canonical_keys():
    """Covers that every result dict has required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_404()):
        results = s.scan(URL)
    for r in results:
        assert "type" in r
        assert "status" in r
        assert "url" in r
