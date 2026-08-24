"""Tests for tblue.scanner.fetch_metadata — FetchMetadataScanner."""

from unittest.mock import MagicMock, patch
from tblue.scanner.fetch_metadata import FetchMetadataScanner

URL = "https://example.com"


def _make_scanner():
    return FetchMetadataScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = {}
    return r


def test_unreachable_pass():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_missing_coop_warns():
    """No COOP header → WARN."""
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>", {})):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("coop" in w["type"].lower() or "opener" in w["type"].lower() for w in warns)


def test_missing_coep_warns():
    """No COEP header → WARN."""
    s = _make_scanner()
    headers = {"cross-origin-opener-policy": "same-origin"}
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>", headers)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("coep" in w["type"].lower() or "embedder" in w["type"].lower() for w in warns)


def test_all_headers_present_pass():
    """COOP + COEP + no API endpoints → PASS."""
    s = _make_scanner()
    headers = {
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-embedder-policy": "require-corp",
    }

    def se(url, **kw):
        # Return 404 for all probed API paths so no API findings are generated
        return _resp(404, "", headers)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] == "FAIL" for r in results)


def test_api_endpoint_accepts_cross_site_without_corp_warns():
    """API endpoint exists and accepts cross-site requests without CORP → WARN."""
    s = _make_scanner()
    main_headers = {
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-embedder-policy": "require-corp",
    }

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>", main_headers)
        if "/api/" in url:
            # Return 200 with no CORP header (no matter what headers are passed)
            return _resp(200, '{"data": []}', {})
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("corp" in w["type"].lower() or "cross-site" in w["type"].lower()
               or "fetch metadata" in w["type"].lower() for w in warns)


def test_api_endpoint_with_corp_header_no_warn():
    """API endpoint with CORP: same-site → no WARN for that endpoint."""
    s = _make_scanner()
    good_headers = {
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-embedder-policy": "require-corp",
        "cross-origin-resource-policy": "same-site",
    }

    def se(url, **kw):
        return _resp(200, '{"ok": true}', good_headers)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    corp_warns = [r for r in results
                  if r["status"] == "WARN" and "corp" in r["type"].lower()]
    assert len(corp_warns) == 0


def test_unusual_coop_value_warns():
    """COOP: unsafe-none is non-standard → WARN."""
    s = _make_scanner()
    headers = {"cross-origin-opener-policy": "unsafe-none"}

    def se(url, **kw):
        return _resp(200, "", headers)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("unusual" in w["type"].lower() or "coop" in w["type"].lower() for w in warns)


def test_form_action_endpoint_without_corp_warns():
    """Form action endpoint accessible cross-site without CORP → WARN."""
    s = _make_scanner()
    main_headers = {
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-embedder-policy": "require-corp",
    }
    html = '<html><body><form action="/submit" method="post"><input type="submit"></form></body></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html, main_headers)
        if "/submit" in url:
            return _resp(200, "OK", {})  # no CORP, accepts cross-site
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("form" in w["type"].lower() or "corp" in w["type"].lower()
               or "fetch metadata" in w["type"].lower() for w in warns)


def test_api_endpoint_returns_404_no_finding():
    """API endpoint returning 404 is not flagged."""
    s = _make_scanner()
    main_headers = {
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-embedder-policy": "require-corp",
    }

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>", main_headers)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    # Should be PASS since all probed endpoints return 404 (don't exist)
    assert any(r["status"] == "PASS" for r in results)


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_api_probe_cross_site_returns_none_continues():
    """Baseline succeeds (200), cross-site GET returns None → continue at line 228."""
    s = _make_scanner()
    main_headers = {
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-embedder-policy": "require-corp",
    }

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>", main_headers)
        headers_arg = kw.get("headers", {})
        if headers_arg and "Sec-Fetch-Site" in headers_arg:
            return None  # cross-site probe returns None
        return _resp(200, "{}", {})  # baseline returns 200

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_api_probe_raises_continues():
    """http.get raises in _probe_api_endpoints loop → except Exception: continue at lines 258-259."""
    s = _make_scanner()
    main_headers = {
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-embedder-policy": "require-corp",
    }

    def se(url, **kw):
        if url == URL:
            return _resp(200, "<html></html>", main_headers)
        raise RuntimeError("connection refused")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_form_action_absolute_url_probed():
    """Form action with absolute URL → probe_url = action at line 270."""
    s = _make_scanner()
    main_headers = {
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-embedder-policy": "require-corp",
    }
    html = '<html><body><form action="https://api.example.com/submit"><input type="submit"></form></body></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html, main_headers)
        if "api.example.com" in url:
            return _resp(200, "OK", {})  # accepts cross-site, no CORP
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("form" in w["type"].lower() or "corp" in w["type"].lower()
               or "fetch" in w["type"].lower() for w in warns)


def test_form_action_probe_returns_none_continues():
    """GET for form action URL returns None → if r is None: continue at line 276."""
    s = _make_scanner()
    main_headers = {
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-embedder-policy": "require-corp",
    }
    html = '<html><body><form action="/submit"><input type="submit"></form></body></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html, main_headers)
        return None  # form probe returns None (and API baselines also None → skip)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_form_action_probe_inner_raises_continues():
    """GET raises for form action URL → except Exception: continue at lines 295-296."""
    s = _make_scanner()
    main_headers = {
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-embedder-policy": "require-corp",
    }
    html = '<html><body><form action="/submit"><input type="submit"></form></body></html>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html, main_headers)
        if "/submit" in url:
            raise RuntimeError("timeout")
        return _resp(404)  # API baselines skip (404), form probe raises

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_form_action_findall_raises_outer_passes():
    """_FORM_ACTION_RE.findall raises → outer except Exception: pass at lines 297-298."""
    s = _make_scanner()
    main_headers = {
        "cross-origin-opener-policy": "same-origin",
        "cross-origin-embedder-policy": "require-corp",
    }
    html = '<form action="/submit"></form>'

    def se(url, **kw):
        if url == URL:
            return _resp(200, html, main_headers)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        with patch("tblue.scanner.fetch_metadata._FORM_ACTION_RE") as mock_re:
            mock_re.findall.side_effect = RuntimeError("regex crashed")
            results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
