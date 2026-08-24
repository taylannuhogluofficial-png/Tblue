"""Extra branch coverage for tblue.scanner.clickjacking."""

from unittest.mock import MagicMock, patch
from tblue.scanner.clickjacking import ClickjackingScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return ClickjackingScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def test_no_response_returns_pass():
    """Covers the None-response early-exit path."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert results[0]["status"] == "PASS"


def test_xfo_deny_returns_pass():
    """Covers the protected branch when X-Frame-Options: DENY is set."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>",
                                                         {"X-Frame-Options": "DENY"})):
        results = s.scan(URL)
    assert all(r["status"] == "PASS" for r in results)


def test_no_headers_no_framebusting_fails():
    """Covers the FAIL branch when no XFO, no CSP, no JS framebusting."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html><body>content</body></html>", {})):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_js_only_framebusting_warns():
    """Covers the WARN branch when only JS frame-busting is present (no HTTP headers)."""
    s = _scanner()
    html = """
    <html><body>
    <script>if (top.location !== self.location) top.location = self.location;</script>
    </body></html>
    """
    with patch.object(s.http, "get", return_value=_resp(200, html, {})):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_allow_from_xfo_warns():
    """Covers the ALLOW-FROM deprecation warning branch."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>",
                                                         {"X-Frame-Options": "ALLOW-FROM https://partner.com"})):
        results = s.scan(URL)
    assert any(r["status"] in ("WARN", "FAIL") for r in results)


def test_csp_frame_ancestors_none_protects():
    """Covers the CSP frame-ancestors 'none' protection branch."""
    s = _scanner()
    headers = {"Content-Security-Policy": "frame-ancestors 'none'; default-src 'self'"}
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>", headers)):
        results = s.scan(URL)
    assert all(r["status"] == "PASS" for r in results)
