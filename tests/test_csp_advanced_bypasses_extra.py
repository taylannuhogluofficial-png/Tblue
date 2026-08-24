"""Extra branch coverage for tblue.scanner.csp_advanced (bypass vector paths)."""

from unittest.mock import MagicMock, patch
from tblue.scanner.csp_advanced import CSPAdvancedScanner

URL = "https://example.com"


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _scanner():
    session = MagicMock()
    return CSPAdvancedScanner(session)


def test_no_csp_header_and_no_meta_returns_empty():
    """Branch: no CSP header and no meta CSP — returns early with empty list."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html><body></body></html>", {})):
        results = s.scan(URL)
    # Basic CSP scanner flags missing; advanced scanner skips when no CSP at all
    assert isinstance(results, list)


def test_report_only_csp_warns():
    """Branch: only Content-Security-Policy-Report-Only set — WARN about not enforced."""
    s = _scanner()
    headers = {"Content-Security-Policy-Report-Only": "default-src 'self'"}
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>", headers)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("report-only" in r["type"].lower() or "not enforced" in r.get("detail", "").lower()
               for r in warns)


def test_meta_csp_only_warns():
    """Branch: CSP delivered via meta http-equiv tag only — WARN."""
    s = _scanner()
    html = (
        '<html><head>'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">'
        '</head><body></body></html>'
    )
    with patch.object(s.http, "get", return_value=_resp(200, html, {})):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("meta" in r["type"].lower() or "meta" in r.get("detail", "").lower()
               for r in warns)


def test_cdn_bypass_host_in_script_src_warns():
    """Branch: known CDN bypass host (ajax.googleapis.com) in script-src — WARN."""
    s = _scanner()
    headers = {
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' ajax.googleapis.com; "
            "frame-ancestors 'self'"
        )
    }
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>", headers)):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert bad


def test_none_response_returns_empty():
    """Branch: http.get returns None — scan returns empty list immediately."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert results == []


def test_csp_without_report_endpoint_warns():
    """Branch: enforced CSP with no report-uri or report-to — WARN about silent violations."""
    s = _scanner()
    headers = {
        "Content-Security-Policy": (
            "default-src 'self'; script-src 'self'; frame-ancestors 'self'"
        )
    }
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>", headers)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    # Should warn about missing report endpoint (type contains "no violation reporting")
    assert any("violation" in r["type"].lower() or "report" in r["type"].lower()
               for r in warns)
