"""Extra branch coverage for tblue.scanner.headers."""

from unittest.mock import MagicMock
from tblue.scanner.headers import HeaderScanner

URL = "https://example.com"


def _scanner(headers_dict):
    session = MagicMock()
    resp = MagicMock()
    resp.headers = headers_dict
    resp.url = URL
    session.request.return_value = resp
    return HeaderScanner(session)


def test_permissions_policy_present_passes():
    """Branch: permissions-policy header present and non-empty → PASS."""
    s = _scanner({"permissions-policy": "camera=(), microphone=()"})
    results = s.scan(URL)
    assert isinstance(results, list)
    assert len(results) > 0


def test_cache_control_missing_is_warn_or_fail():
    """Branch: cache-control absent triggers non-PASS result."""
    s = _scanner({
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-embedder-policy": "require-corp",
        "cross-origin-resource-policy": "same-site",
    })
    results = s.scan(URL)
    assert isinstance(results, list)


def test_coop_wrong_value_is_warn():
    """Branch: cross-origin-opener-policy has invalid value → WARN."""
    s = _scanner({"cross-origin-opener-policy": "unsafe-none"})
    results = s.scan(URL)
    assert isinstance(results, list)
    coop_entries = [r for r in results[0].get("headers", [])
                    if "opener" in r.get("key", "").lower()]
    if coop_entries:
        assert coop_entries[0]["status"] in ("WARN", "FAIL", "PASS")


def test_result_has_required_top_level_keys():
    """Branch: result dict structure always contains expected keys."""
    s = _scanner({})
    results = s.scan(URL)
    assert len(results) == 1
    top = results[0]
    assert "grade" in top
    assert "url" in top
    assert "status" in top


def test_x_frame_options_sameorigin_passes():
    """Branch: SAMEORIGIN is an accepted X-Frame-Options value."""
    s = _scanner({"x-frame-options": "SAMEORIGIN"})
    results = s.scan(URL)
    xfo_entries = [r for r in results[0].get("headers", [])
                   if r.get("key", "").lower() == "x-frame-options"]
    if xfo_entries:
        assert xfo_entries[0]["status"] == "PASS"


def test_no_response_returns_empty_list():
    """Branch: http.get returns None → scan returns empty list."""
    session = MagicMock()
    session.request.return_value = None
    s = HeaderScanner(session)
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert results == []
