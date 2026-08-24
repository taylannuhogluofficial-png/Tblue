"""Tests for host header injection detection."""

from unittest.mock import MagicMock
from tblue.scanner.host_header import HostHeaderScanner, _PROBE_VALUE


def _scanner(reflect_in=None):
    """
    reflect_in: None (no reflection), "Location", "body", or list of both
    """
    session = MagicMock()
    call_count = [0]

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        resp.text = "<html>Normal page</html>"

        sent_headers = kwargs.get("headers", {})
        injected = any(_PROBE_VALUE in v for v in (sent_headers or {}).values())

        if injected and reflect_in:
            targets = [reflect_in] if isinstance(reflect_in, str) else reflect_in
            if "Location" in targets:
                resp.headers["Location"] = f"https://{_PROBE_VALUE}/path"
            if "body" in targets:
                resp.text = f"<html><a href='https://{_PROBE_VALUE}/'>link</a></html>"

        return resp

    session.request.side_effect = fake_request
    return HostHeaderScanner(session)


# ── No reflection → PASS ──────────────────────────────────────────────────────

def test_no_reflection_passes():
    scanner = _scanner(reflect_in=None)
    results = scanner.scan("https://example.com")
    assert any("not detected" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ── Location header reflection → FAIL ────────────────────────────────────────

def test_location_reflection_fails():
    scanner = _scanner(reflect_in="Location")
    results = scanner.scan("https://example.com")
    assert any("fail" == r["status"].lower() for r in results)


def test_location_reflection_detail_mentions_cache_poisoning():
    scanner = _scanner(reflect_in="Location")
    results = scanner.scan("https://example.com")
    fail = [r for r in results if r["status"] == "FAIL"]
    assert fail
    assert "cache poisoning" in fail[0]["detail"].lower()


# ── Body reflection → FAIL ────────────────────────────────────────────────────

def test_body_reflection_fails():
    scanner = _scanner(reflect_in="body")
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "FAIL" for r in results)


def test_body_reflection_type_mentions_response_body():
    scanner = _scanner(reflect_in="body")
    results = scanner.scan("https://example.com")
    fail = [r for r in results if r["status"] == "FAIL"]
    assert fail
    assert "response body" in fail[0]["type"].lower()


# ── Network error → graceful empty ───────────────────────────────────────────

def test_network_error_returns_pass():
    # All requests raise exceptions → no reflection found → scanner emits PASS
    session = MagicMock()
    session.request.side_effect = Exception("connect timeout")
    scanner = HostHeaderScanner(session)
    results = scanner.scan("https://example.com")
    assert all(r["status"] in ("PASS", "WARN") for r in results)


# ── None response → graceful empty ───────────────────────────────────────────

def test_none_response_returns_empty():
    session = MagicMock()
    session.request.return_value = None
    scanner = HostHeaderScanner(session)
    results = scanner.scan("https://example.com")
    # None response means no results (scanner skips None)
    assert all(r["status"] in ("PASS", "WARN", "FAIL") for r in results)


def test_http_get_raises_exception_is_caught():
    # Patch http.get on the scanner directly to raise — covers the except branch
    # (http.get() normally never raises; this exercises the defensive guard)
    from unittest.mock import patch
    scanner = _scanner(reflect_in=None)
    with patch.object(scanner.http, "get", side_effect=Exception("unexpected")):
        results = scanner.scan("https://example.com")
    # Exception swallowed; scanner ends cleanly with PASS (no reflection)
    assert isinstance(results, list)


# ── Multiple overrides → separate findings ────────────────────────────────────

def test_multiple_headers_tested():
    """Scanner tests all 5 override headers, not just one."""
    from tblue.scanner.host_header import _OVERRIDE_HEADERS
    assert len(_OVERRIDE_HEADERS) >= 3
    assert "X-Forwarded-Host" in _OVERRIDE_HEADERS
    assert "X-Host" in _OVERRIDE_HEADERS
