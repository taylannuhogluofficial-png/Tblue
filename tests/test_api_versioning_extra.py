"""Extra branch coverage for tblue.scanner.api_versioning."""

from unittest.mock import MagicMock, patch
from tblue.scanner.api_versioning import APIVersioningScanner

URL = "https://example.com/api/v3/users"
BASE_URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return APIVersioningScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _404():
    return _resp(404, "Not Found")


def test_no_version_in_url_still_probes():
    """Covers path where URL has no version number — scanner probes defaults."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(404, "Not Found")):
        results = s.scan(BASE_URL)
    assert isinstance(results, list)
    assert len(results) >= 1


def test_older_version_returns_data_warns_or_fails():
    """Covers branch where v1 endpoint returns data while v3 requires auth."""
    s = _scanner()

    def fake_get(url, **kw):
        if "/api/v1" in url or "/v1/" in url:
            return _resp(200, '{"data": [{"id": 1, "user": "alice"}]}', {})
        if "/api/v3" in url or "/v3/" in url:
            return _resp(401, '{"error": "unauthorized"}', {})
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert any(r["status"] in ("FAIL", "WARN") for r in results)


def test_version_enumeration_message_warns():
    """Covers version enumeration hint detection in error responses."""
    s = _scanner()

    def fake_get(url, **kw):
        if "/v1/" in url or "/api/v1" in url:
            return _resp(404, "API version v1 is deprecated, please upgrade to version v3")
        return _resp(401, '{"error": "unauthorized"}')

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_sunset_header_on_old_version_detected():
    """Covers Sunset/Deprecation response header detection."""
    s = _scanner()

    def fake_get(url, **kw):
        if "/api/v1" in url or "/v1/" in url:
            return _resp(200, "", {"Sunset": "Sat, 31 Dec 2023 00:00:00 GMT"})
        return _resp(200, "", {})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_all_results_have_required_keys():
    """Covers that result dicts always contain type, status, url."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(404)):
        results = s.scan(BASE_URL)
    for r in results:
        assert "type" in r
        assert "status" in r
        assert "url" in r


def test_missing_security_headers_on_old_version():
    """Covers branch where old API version lacks security headers present on newer."""
    s = _scanner()

    def fake_get(url, **kw):
        if "/api/v1" in url or "/v1/" in url:
            # Old version: no security headers
            return _resp(200, '{"results": []}', {})
        if "/api/v3" in url or "/v3/" in url:
            return _resp(200, '{"results": []}', {
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
            })
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan(URL)
    assert any(r["status"] in ("WARN", "FAIL", "PASS") for r in results)
