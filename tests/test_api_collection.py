"""Tests for tblue.scanner.api_collection — APICollectionScanner."""

from unittest.mock import MagicMock, patch
from tblue.scanner.api_collection import APICollectionScanner

URL = "https://example.com"


def _make_scanner():
    return APICollectionScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = {}
    return r


# --- Collection fixtures ---

_POSTMAN_V2_BODY = """{
  "info": {
    "_postman_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "My API",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Get Users",
      "request": {
        "method": "GET",
        "header": [
          {"key": "Authorization", "value": "Bearer {{auth_token}}"}
        ],
        "url": {"raw": "{{base_url}}/api/users", "host": ["{{base_url}}"], "path": ["api","users"]}
      }
    }
  ]
}"""

_POSTMAN_V2_WITH_CREDS = """{
  "info": {
    "_postman_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "Production API",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Get Users",
      "request": {
        "method": "GET",
        "header": [
          {"key": "Authorization", "value": "Bearer eyJhbGciOiJSUzI1NiJ9.PRODUCTION_TOKEN_HERE"},
          {"key": "x-api-key", "value": "sk-prod-abc123XYZ456789DEF"}
        ],
        "url": {"raw": "https://api.prod.example.com/users"}
      }
    }
  ]
}"""

_INSOMNIA_BODY = """{
  "_type": "export",
  "__export_format": 4,
  "__export_date": "2024-01-01T00:00:00.000Z",
  "__export_source": "insomnia.desktop.app:v2024.1.0",
  "resources": [
    {
      "_id": "req_001",
      "_type": "request",
      "name": "Get Items",
      "method": "GET",
      "url": "{{base_url}}/api/items",
      "headers": [{"name": "Authorization", "value": "Bearer {{auth_token}}"}]
    }
  ]
}"""

_INSOMNIA_WITH_CREDS = """{
  "_type": "export",
  "__export_format": 4,
  "resources": [
    {
      "_id": "env_001",
      "_type": "environment",
      "name": "Production",
      "data": {
        "base_url": "https://api.prod.example.com",
        "auth_token": "prod-secret-token-abc123"
      }
    }
  ]
}"""

_HOPPSCOTCH_BODY = """{
  "v": 1,
  "id": "coll_abcdef",
  "name": "API Workspace",
  "folders": [],
  "requests": [
    {
      "id": "req_001",
      "name": "Get Data",
      "method": "GET",
      "endpoint": "https://api.example.com/data",
      "headers": []
    }
  ]
}"""


def test_unreachable_returns_pass():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_clean_target_no_collections_pass():
    """No collection files accessible → PASS."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html>Homepage</html>")
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] in ("FAIL", "WARN") for r in results)


def test_postman_collection_exposed_fails():
    """Postman v2.1 collection at /postman_collection.json → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/postman_collection.json":
            return _resp(200, _POSTMAN_V2_BODY)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any(
        "postman" in r["type"].lower() or "collection" in r["type"].lower()
        for r in fails
    )


def test_postman_collection_with_hardcoded_creds_fails():
    """Postman collection with Bearer token and x-api-key in headers → FAIL (creds detected)."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/api.postman_collection.json":
            return _resp(200, _POSTMAN_V2_WITH_CREDS)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any(r for r in fails)
    # Detail should mention credentials
    detail_text = " ".join(r.get("detail", "") for r in fails)
    assert "bearer" in detail_text.lower() or "token" in detail_text.lower() or "credential" in detail_text.lower()


def test_insomnia_collection_exposed_fails():
    """Insomnia workspace at /insomnia.json → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/insomnia.json":
            return _resp(200, _INSOMNIA_BODY)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any(
        "insomnia" in r["type"].lower() or "collection" in r["type"].lower()
        for r in fails
    )


def test_insomnia_with_env_creds_detected():
    """Insomnia export with environment currentValue for prod token → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/insomnia.json":
            return _resp(200, _INSOMNIA_WITH_CREDS)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any(r for r in fails)


def test_hoppscotch_collection_exposed_fails():
    """Hoppscotch collection at /hoppscotch.json → FAIL."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/hoppscotch.json":
            return _resp(200, _HOPPSCOTCH_BODY)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any(
        "hoppscotch" in r["type"].lower() or "collection" in r["type"].lower()
        for r in fails
    )


def test_generic_json_at_collection_path_not_flagged():
    """Regular JSON at /postman_collection.json without collection structure → not flagged."""
    s = _make_scanner()
    generic_json = '{"status": "ok", "message": "Hello world"}'

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url.endswith("postman_collection.json"):
            return _resp(200, generic_json)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert not any(r["status"] == "FAIL" for r in results)


def test_html_404_at_collection_path_not_flagged():
    """HTML 404 page served at collection path → not flagged."""
    s = _make_scanner()
    html_404 = "<html><body><h1>404 Not Found</h1></body></html>"

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        # Some servers return 200 with 404-content for all paths
        return _resp(200, html_404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    # HTML won't match collection format validators
    fails = [r for r in results if r["status"] == "FAIL"]
    assert len(fails) == 0


def test_short_body_not_flagged():
    """Tiny 200 body at collection path → not flagged (min body size check)."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        return _resp(200, "{}")  # less than 20 chars

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert not any(r["status"] == "FAIL" for r in results)


def test_exception_during_probe_handled_gracefully():
    """Network error during collection probe → scanner continues, returns PASS."""
    s = _make_scanner()
    call_count = [0]

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        call_count[0] += 1
        if call_count[0] == 1:
            raise ConnectionError("timed out")
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_postman_env_export_with_current_value_detected():
    """Postman environment export with currentValue → FAIL with credential detection."""
    s = _make_scanner()
    # Postman exported environment format
    postman_env = """{
  "info": {
    "_postman_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "Production Env",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [],
  "variable": [
    {
      "key": "auth_token",
      "value": "prod-auth-token-abc123",
      "currentValue": "eyJhbGciOiJSUzI1NiJ9.LIVE_PROD_TOKEN_ABCDEFGH",
      "type": "secret"
    },
    {
      "key": "api_key",
      "currentValue": "sk-live-ABCDEFGHIJKLMNOP",
      "type": "secret"
    }
  ]
}"""

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/postman_collection.json":
            return _resp(200, postman_env)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any(r for r in fails)
    detail_text = " ".join(r.get("detail", "") for r in fails)
    assert "environment variable" in detail_text.lower() or "credential" in detail_text.lower()


def test_basic_auth_in_collection_detected():
    """Postman collection with Basic auth in header value → FAIL."""
    s = _make_scanner()
    postman_basic_auth = """{
  "info": {
    "_postman_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
    "name": "Internal API",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Auth endpoint",
      "request": {
        "method": "GET",
        "header": [
          {"key": "Authorization", "value": "Basic dXNlcjpwYXNzd29yZA=="}
        ]
      }
    }
  ]
}"""

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/postman_collection.json":
            return _resp(200, postman_basic_auth)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any(r for r in fails)
    detail_text = " ".join(r.get("detail", "") for r in fails)
    assert "basic auth" in detail_text.lower() or "credential" in detail_text.lower()


def test_aws_key_in_postman_collection_detected():
    """Postman collection with AWS access key ID → FAIL with credential info in detail."""
    s = _make_scanner()
    postman_with_aws = _POSTMAN_V2_BODY.replace(
        '"key": "Authorization", "value": "Bearer {{auth_token}}"',
        '"key": "x-aws-access-key", "value": "AKIAIOSFODNN7EXAMPLE"'
    )

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url == "https://example.com/postman_collection.json":
            return _resp(200, postman_with_aws)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any(r for r in fails)
    detail_text = " ".join(r.get("detail", "") for r in fails)
    assert "aws" in detail_text.lower() or "credential" in detail_text.lower()
