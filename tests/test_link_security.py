"""Tests for tblue.scanner.link_security — LinkSecurityScanner."""

from unittest.mock import MagicMock, patch
from tblue.scanner.link_security import LinkSecurityScanner

URL = "https://example.com"


def _make_scanner():
    return LinkSecurityScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = {}
    return r


def test_unreachable_returns_pass():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_clean_page_no_issues_pass():
    """Page with no target=_blank and no external iframes → PASS."""
    s = _make_scanner()
    html = (
        '<html><body>'
        '<a href="/about">About</a>'
        '<a href="https://example.com/page" rel="noopener noreferrer" target="_blank">Safe</a>'
        '</body></html>'
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] in ("FAIL", "WARN") for r in results)


def test_external_target_blank_without_noopener_fails():
    """External <a target='_blank'> without rel='noopener' → FAIL."""
    s = _make_scanner()
    html = (
        '<html><body>'
        '<a href="https://evil.com/article" target="_blank">Read more</a>'
        '</body></html>'
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("tabnab" in r["type"].lower() or "noopener" in r["type"].lower() for r in fails)


def test_internal_target_blank_without_noopener_warns():
    """Internal <a target='_blank'> without rel='noopener' → WARN (not FAIL)."""
    s = _make_scanner()
    html = (
        '<html><body>'
        '<a href="/internal/page" target="_blank">Open</a>'
        '</body></html>'
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    status_set = {r["status"] for r in results}
    assert "FAIL" not in status_set
    assert "WARN" in status_set


def test_target_blank_with_noopener_passes():
    """<a target='_blank' rel='noopener noreferrer'> → no flag."""
    s = _make_scanner()
    html = (
        '<html><body>'
        '<a href="https://external.com" target="_blank" rel="noopener noreferrer">Safe</a>'
        '<a href="https://other.com" target="_blank" rel="noreferrer">Also safe</a>'
        '</body></html>'
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    # noreferrer implies noopener, so neither should flag
    assert not any(r["status"] == "FAIL" for r in results)


def test_external_iframe_without_sandbox_fails():
    """External iframe without sandbox attribute → FAIL."""
    s = _make_scanner()
    html = (
        '<html><body>'
        '<iframe src="https://ads.external.com/banner.html" width="300" height="250"></iframe>'
        '</body></html>'
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("iframe" in r["type"].lower() or "sandbox" in r["type"].lower() for r in fails)


def test_external_iframe_with_sandbox_passes():
    """External iframe with sandbox attribute → no flag."""
    s = _make_scanner()
    html = (
        '<html><body>'
        '<iframe src="https://ads.external.com/banner.html" '
        'sandbox="allow-scripts allow-same-origin" width="300" height="250"></iframe>'
        '</body></html>'
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    assert not any(r["status"] == "FAIL" for r in results)


def test_internal_iframe_without_sandbox_not_flagged():
    """Same-origin iframe without sandbox → not flagged (only external iframes matter)."""
    s = _make_scanner()
    html = (
        '<html><body>'
        '<iframe src="/dashboard/embed" width="600" height="400"></iframe>'
        '</body></html>'
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    assert not any(r["status"] == "FAIL" for r in results)


def test_window_open_without_noopener_warns():
    """window.open(url, '_blank') without noopener feature string → WARN."""
    s = _make_scanner()
    html = (
        '<html><body>'
        '<script>'
        "function share(){ window.open('https://twitter.com/share', '_blank'); }"
        '</script>'
        '</body></html>'
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("window.open" in r["type"].lower() or "noopener" in r["type"].lower() for r in warns)


def test_window_open_with_noopener_passes():
    """window.open(url, '_blank', 'noopener,noreferrer') → no flag."""
    s = _make_scanner()
    html = (
        '<html><body>'
        '<script>'
        "function share(){ window.open('https://twitter.com/share', '_blank', 'noopener,noreferrer'); }"
        '</script>'
        '</body></html>'
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    warns_about_open = [
        r for r in results
        if r["status"] == "WARN" and "window.open" in r["type"].lower()
    ]
    assert len(warns_about_open) == 0


def test_tracking_domain_prefetch_warns():
    """dns-prefetch to google-analytics.com → WARN."""
    s = _make_scanner()
    html = (
        '<html><head>'
        '<link rel="dns-prefetch" href="https://www.google-analytics.com">'
        '<link rel="preconnect" href="https://www.googletagmanager.com">'
        '</head><body></body></html>'
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("prefetch" in r["type"].lower() or "tracking" in r["type"].lower() for r in warns)


def test_non_tracking_prefetch_not_flagged():
    """dns-prefetch to own CDN (not a known tracker) → no flag."""
    s = _make_scanner()
    html = (
        '<html><head>'
        '<link rel="preconnect" href="https://cdn.example.com">'
        '<link rel="dns-prefetch" href="https://fonts.gstatic.com">'
        '</head><body></body></html>'
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    # fonts.gstatic.com is not in the tracking domain list
    tracking_warns = [
        r for r in results
        if r.get("status") == "WARN" and "tracking" in r.get("type", "").lower()
    ]
    assert len(tracking_warns) == 0


def test_protocol_relative_external_url_detected():
    """//external.com/page (protocol-relative) target=_blank without noopener → FAIL."""
    s = _make_scanner()
    html = (
        '<html><body>'
        '<a href="//evil-other.com/page" target="_blank">Protocol-relative link</a>'
        '</body></html>'
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("tabnab" in r["type"].lower() or "noopener" in r["type"].lower() for r in fails)


def test_fragment_and_mailto_links_not_flagged():
    """#fragment and mailto: target=_blank links are not flagged (non-external)."""
    s = _make_scanner()
    html = (
        '<html><body>'
        '<a href="#section" target="_blank">Jump</a>'
        '<a href="mailto:user@example.com" target="_blank">Email</a>'
        '<a href="tel:+1234567890" target="_blank">Call</a>'
        '</body></html>'
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    # Fragment/mailto/tel hrefs are internal, should be WARN at most (not FAIL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert len(fails) == 0


def test_multiple_issues_all_reported():
    """Page with both external no-sandbox iframe and target=_blank without noopener → both flagged."""
    s = _make_scanner()
    html = (
        '<html><body>'
        '<a href="https://evil.com" target="_blank">Click</a>'
        '<iframe src="https://ads.example.org/frame"></iframe>'
        '</body></html>'
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert len(fails) >= 2
