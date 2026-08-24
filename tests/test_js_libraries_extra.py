"""Extra branch coverage for tblue.scanner.js_libraries."""

from unittest.mock import MagicMock, patch
from tblue.scanner.js_libraries import JSLibraryScanner, _check_vuln, _ver_lt

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return JSLibraryScanner(session)


def _resp(body="", status=200):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    r.url = URL
    return r


def test_no_response_returns_empty():
    """Branch: GET returns None → empty result list."""
    s = _scanner()
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert results == []


def test_no_lib_versions_detected_is_pass():
    """Branch: HTML has no detectable library version strings → PASS."""
    s = _scanner()
    s.http.get = MagicMock(return_value=_resp("<html><script src='/app.js'></script></html>"))
    results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_outdated_jquery_is_fail():
    """Branch: jQuery 2.x detected (< 3.5.0) → FAIL."""
    s = _scanner()
    html = '<html><script src="/jquery-2.2.4.min.js"></script></html>'
    s.http.get = MagicMock(return_value=_resp(html))
    results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("jquery" in r["type"].lower() for r in fails)


def test_current_jquery_is_pass():
    """Branch: jQuery 3.7.0 (above all vuln thresholds) → PASS."""
    s = _scanner()
    html = '<html><script src="/jquery-3.7.0.min.js"></script></html>'
    s.http.get = MagicMock(return_value=_resp(html))
    results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_inline_comment_version_detected():
    """Branch: inline JS comment '/*! jQuery v1.12.4 */' triggers detection."""
    s = _scanner()
    html = '<html><script>/*! jQuery v1.12.4 */ var x=1;</script></html>'
    s.http.get = MagicMock(return_value=_resp(html))
    results = s.scan(URL)
    fails = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert fails


def test_medium_severity_vuln_is_warn():
    """Branch: bootstrap 3.3.0 (< 3.4.1, MEDIUM) → WARN."""
    s = _scanner()
    html = '<html><script src="/bootstrap-3.3.0.min.js"></script></html>'
    s.http.get = MagicMock(return_value=_resp(html))
    results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_ver_lt_helper():
    """Branch: _ver_lt correctly compares version strings."""
    assert _ver_lt("3.4.0", "3.5.0") is True
    assert _ver_lt("3.5.0", "3.5.0") is False
    assert _ver_lt("4.0.0", "3.5.0") is False
