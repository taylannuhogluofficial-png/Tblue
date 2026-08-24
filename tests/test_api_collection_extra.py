"""Extra branch coverage for tblue.scanner.api_collection."""

from unittest.mock import MagicMock, patch
from tblue.scanner.api_collection import APICollectionScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return APICollectionScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _404():
    return _resp(404, "Not Found")


def test_no_manifests_found_returns_pass():
    """Covers the clean branch where no collection files are exposed."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_404()):
        results = s.scan(URL)
    assert all(r["status"] == "PASS" for r in results)


def test_postman_v2_collection_detected():
    """Covers the Postman v2 collection format detection branch."""
    s = _scanner()
    postman_body = (
        '{"info": {"_postman_id": "abc123def456", "name": "My API", "schema": '
        '"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"}, '
        '"item": [{"name": "Get users", "request": {"method": "GET"}}]}'
    )

    def fake_get(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if "postman_collection" in url or url.endswith("/package.json") or url.endswith("/collection.json"):
            return _resp(200, postman_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert any(r["status"] in ("FAIL", "WARN") for r in results)


def test_insomnia_collection_with_bearer_token_flagged():
    """Covers Insomnia collection detection with embedded Bearer token."""
    s = _scanner()
    insomnia_body = (
        '{"__export_format": 4, "_type": "export", "resources": ['
        '{"_type": "request", "method": "GET", "url": "https://api.example.com",'
        ' "headers": [{"name": "Authorization", "value": "Bearer eyJhbGciOiJSUzI1NiJ9.token.sig"}]}'
        ']}'
    )

    def fake_get(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if "insomnia" in url:
            return _resp(200, insomnia_body)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_result_always_has_required_keys():
    """Covers that all results have the mandatory dict keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        results = s.scan(URL)
    for r in results:
        assert "type" in r
        assert "status" in r
        assert "url" in r


def test_200_response_not_matching_schema_skipped():
    """Covers the branch where a 200 response does not match any collection schema."""
    s = _scanner()

    def fake_get(url, **kw):
        # returns 200 but body is just generic JSON
        return _resp(200, '{"message": "OK", "data": []}')

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    # No collection schema match → PASS
    assert all(r["status"] == "PASS" for r in results)


def test_postman_v1_collection_detected():
    """Covers the Postman v1 format detection branch."""
    s = _scanner()
    postman_v1 = (
        '{"id": "col-123", "name": "My Collection", '
        '"collection_id": "deadbeef-1234-5678-9012-abcdef012345", '
        '"requests": [{"id": "req-1", "method": "GET", "url": "https://api.example.com/users"}]}'
    )

    def fake_get(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if url.endswith("/collection.json") or "postman" in url:
            return _resp(200, postman_v1)
        return _404()

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert any(r["status"] in ("FAIL", "WARN") for r in results)
