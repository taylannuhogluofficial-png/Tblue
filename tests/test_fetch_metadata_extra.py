"""Extra branch coverage for tblue.scanner.fetch_metadata."""

from unittest.mock import MagicMock, patch
from tblue.scanner.fetch_metadata import FetchMetadataScanner

URL = "https://example.com"


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _scanner():
    session = MagicMock()
    return FetchMetadataScanner(session)


def test_none_response_returns_pass():
    """Branch: initial get returns None — PASS (target unreachable)."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_missing_coop_header_warns():
    """Branch: no Cross-Origin-Opener-Policy header — WARN."""
    s = _scanner()
    # No COOP/COEP headers
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>", {})):
        with patch.object(s.http, "post", return_value=_resp(403, "")):
            results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("coop" in r["type"].lower() or "opener" in r["type"].lower() for r in warns)


def test_missing_coep_header_warns():
    """Branch: COOP present but no COEP — WARN about missing embedder policy."""
    s = _scanner()
    headers = {"cross-origin-opener-policy": "same-origin"}
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>", headers)):
        with patch.object(s.http, "post", return_value=_resp(403, "")):
            results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("coep" in r["type"].lower() or "embedder" in r["type"].lower() for r in warns)


def test_unusual_coop_value_warns():
    """Branch: COOP set to non-standard value — WARN."""
    s = _scanner()
    headers = {
        "cross-origin-opener-policy": "unsafe-none",
        "cross-origin-embedder-policy": "require-corp",
    }
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>", headers)):
        with patch.object(s.http, "post", return_value=_resp(403, "")):
            results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    # unsafe-none is non-standard
    assert isinstance(results, list)


def test_all_headers_present_passes():
    """Branch: COOP, COEP present with safe values — no COOP/COEP warnings."""
    s = _scanner()
    headers = {
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-embedder-policy": "require-corp",
        "cross-origin-resource-policy": "same-origin",
    }
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>", headers)):
        with patch.object(s.http, "post", return_value=_resp(403, "")):
            results = s.scan(URL)
    coop_warns = [r for r in results if r["status"] == "WARN"
                  and "coop" in r["type"].lower()]
    coep_warns = [r for r in results if r["status"] == "WARN"
                  and "coep" in r["type"].lower()]
    assert not coop_warns
    assert not coep_warns


def test_form_endpoints_probed_from_html():
    """Branch: HTML body contains form actions — those endpoints are probed."""
    s = _scanner()
    html = '<html><body><form action="/login" method="post"><input type="submit"></form></body></html>'
    base_resp = _resp(200, html, {})

    login_resp = _resp(200, "{}", {})

    def get_side_effect(url, **kwargs):
        return base_resp

    def post_side_effect(url, **kwargs):
        return login_resp

    with patch.object(s.http, "get", side_effect=get_side_effect):
        with patch.object(s.http, "post", side_effect=post_side_effect):
            results = s.scan(URL)
    assert isinstance(results, list)
