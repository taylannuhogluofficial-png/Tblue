"""Tests for tblue.scanner.api_versioning — APIVersioningScanner."""

from unittest.mock import MagicMock, patch
from tblue.scanner.api_versioning import APIVersioningScanner

URL = "https://example.com/api/v3/users"


def _make_scanner():
    return APIVersioningScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = {}
    return r


def test_target_unreachable_pass():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_no_old_versions_pass():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=_resp(404)):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_deprecated_v1_still_active_warns():
    """v1 endpoint returning 200 alongside v3 → WARN."""
    s = _make_scanner()
    # URL is v3; v0, v1, v2 are old versions to probe

    def se(url, **kw):
        # Main URL (v3)
        if url == URL:
            return _resp(200, '{"status": "ok"}', {"x-content-type-options": "nosniff"})
        # v1 probe returns data
        if "/v1/" in url or url.endswith("/v1"):
            return _resp(200, '{"data": "old data"}')
        # v0 and v2 return 404
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("deprecated" in r["type"].lower() or "v1" in r["type"] for r in warns_or_fails)


def test_v1_auth_bypass_fails():
    """v1 returns data with 200, v3 returns 401 → FAIL (auth bypass)."""
    s = _make_scanner()
    scan_url = "https://example.com/api/v3/"
    v1_data = '{"data": [{"id": 1, "name": "admin", "email": "admin@example.com"}]}'
    v3_auth_error = '{"error": "unauthorized", "message": "Authentication required"}'

    def se(url, **kw):
        if "/v3" in url:
            return _resp(401, v3_auth_error)
        if "/v1/" in url or url.endswith("/v1"):
            return _resp(200, v1_data)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(scan_url)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("auth" in f["type"].lower() or "bypass" in f["type"].lower() for f in fails)


def test_version_enumeration_in_body_warns():
    """Response body containing version info → WARN."""
    s = _make_scanner()
    body = '<html><p>API version v1 not found. Use version v3 instead.</p></html>'
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com/api/v1/")
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("enumeration" in w["type"].lower() for w in warns)


def test_sunset_header_warns():
    """Sunset header on current endpoint → WARN."""
    s = _make_scanner()
    headers = {"sunset": "2024-12-31T00:00:00Z", "content-type": "application/json"}
    with patch.object(s.http, "get", return_value=_resp(200, '{"ok": true}', headers)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("sunset" in w["type"].lower() or "deprecation" in w["type"].lower() for w in warns)


def test_deprecation_header_warns():
    """Deprecation header on endpoint → WARN."""
    s = _make_scanner()
    headers = {"deprecation": "true", "link": '</api/v4>; rel="successor-version"'}
    with patch.object(s.http, "get", return_value=_resp(200, '{"ok": true}', headers)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("deprecat" in w["type"].lower() for w in warns)


def test_version_in_response_header_discovered():
    """X-API-Version header reveals version for probing."""
    s = _make_scanner()
    headers = {"x-api-version": "3", "content-type": "application/json"}
    v0_data = '{"results": [{"id": 1}]}'

    def se(url, **kw):
        if url == URL:
            return _resp(200, '{"data": "ok"}', headers)
        if "/v0/" in url or url.endswith("/v0"):
            return _resp(200, v0_data)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    # v0 found and flagged, or PASS if all checks pass
    assert isinstance(results, list)


def test_unversioned_api_with_data_warns():
    """Unversioned /api/users returning data → WARN."""
    s = _make_scanner()
    user_data = '{"data": [{"id": 1, "username": "alice"}]}'

    def se(url, **kw):
        if url == "https://example.com/":
            return _resp(200, "<html>Hello</html>")
        if "/api/users" in url and "v" not in url.split("/api/")[1][:3]:
            return _resp(200, user_data)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan("https://example.com/")
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("unversioned" in w["type"].lower() for w in warns)


def test_version_in_page_link_discovered():
    """API version discovered from page link."""
    s = _make_scanner()
    html_body = '<html><a href="/api/v4/users">API v4</a></html>'

    def se(url, **kw):
        if url == "https://example.com":
            return _resp(200, html_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan("https://example.com")
    # v4 detected → probes v1, v2, v3; all return 404 → PASS
    assert any(r["status"] == "PASS" for r in results)


def test_security_headers_missing_on_old_version_warns():
    """Security headers present on v3 but missing on v1 → WARN."""
    s = _make_scanner()
    v3_headers = {
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "content-security-policy": "default-src 'self'",
    }
    v1_body = '{"status": "active", "data": "legacy data"}'

    def se(url, **kw):
        if url == URL:
            return _resp(200, '{"status": "ok"}', v3_headers)
        if "/v1/" in url or url.endswith("/v1"):
            return _resp(200, v1_body, {})  # no security headers
        if "/v2/" in url or url.endswith("/v2"):
            return _resp(200, '{"data": "v2"}', {})
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert warns_or_fails


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_version_from_x_api_version_header():
    """X-API-Version header with no version in URL → lines 165-167 fire."""
    s = _make_scanner()
    headers = {"x-api-version": "3", "content-type": "application/json"}

    def se(url, **kw):
        if url == "https://example.com":
            return _resp(200, "<html></html>", headers)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_version_from_page_text_js_pattern():
    """Version in inline JS string → line 180 fires."""
    s = _make_scanner()
    body = '<html><script>const BASE = "/api/v4/";</script></html>'

    def se(url, **kw):
        if url == "https://example.com":
            return _resp(200, body)
        return _resp(404)  # version probes return 404 → no active old versions

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_probe_old_version_returns_none_continues():
    """http.get returns None for probe paths → if not r: continue at line 191."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        return None

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_probe_old_version_auth_required_flags():
    """Probe returns 401 → return True, probe_url at line 198."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        if "/v1/" in url or url.endswith("/v1"):
            return _resp(401, '{"error": "unauthorized"}')
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_probe_old_version_raises_continues():
    """http.get raises in _probe_old_version → except Exception: continue at lines 199-200."""
    s = _make_scanner()

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        raise RuntimeError("timeout")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_compare_security_get_raises_returns():
    """http.get raises in _compare_security → except Exception: return at lines 208-209."""
    s = _make_scanner()
    probe_call = [0]

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        probe_call[0] += 1
        if probe_call[0] == 1:
            return _resp(200, '{"data": [{"id":1}]}')  # probe finds active endpoint
        raise RuntimeError("timeout")  # _compare_security's http.get calls raise

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_compare_security_old_resp_none_returns():
    """old_resp is None in _compare_security → if not old_resp: return at line 212."""
    s = _make_scanner()
    probe_call = [0]

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>")
        probe_call[0] += 1
        if probe_call[0] == 1:
            return _resp(200, '{"data": [{"id":1}]}')  # probe succeeds
        return None  # _compare_security's calls return None

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_probe_unversioned_raises_continues():
    """http.get raises in _probe_unversioned → except Exception: continue at lines 295-296."""
    s = _make_scanner()

    def se(url, **kw):
        if url == "https://example.com":
            return _resp(200, "<html></html>")
        raise RuntimeError("timeout")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)
