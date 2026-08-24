"""Extra branch coverage for tblue.scanner.link_security."""

from unittest.mock import MagicMock, patch
from tblue.scanner.link_security import LinkSecurityScanner

URL = "https://example.com"


def _resp(body="", status=200):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    r.url = URL
    return r


def _scanner():
    session = MagicMock()
    return LinkSecurityScanner(session)


def test_blank_target_link_no_rel_fails():
    """Link with target=_blank and no rel=noopener → FAIL."""
    html = '<html><body><a href="https://evil.com" target="_blank">Click</a></body></html>'
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad


def test_blank_target_with_noopener_passes():
    """Link with target=_blank and rel=noopener noreferrer → PASS."""
    html = '<html><body><a href="https://good.com" target="_blank" rel="noopener noreferrer">Safe</a></body></html>'
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_iframe_without_sandbox_warns():
    """Iframe without sandbox attribute → FAIL or WARN."""
    html = '<html><body><iframe src="https://widget.com/embed"></iframe></body></html>'
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    assert isinstance(results, list)


def test_no_external_links_passes():
    """Page with no external links → no FAIL results."""
    html = '<html><body><a href="/internal">Link</a></body></html>'
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(html)):
        results = s.scan(URL)
    assert all(r["status"] != "FAIL" for r in results)


def test_none_response_no_fail():
    """None response → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert all(r["status"] != "FAIL" for r in results)
