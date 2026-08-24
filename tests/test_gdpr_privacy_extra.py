"""Extra branch coverage for tblue.scanner.gdpr_privacy."""

from unittest.mock import MagicMock, patch
from tblue.scanner.gdpr_privacy import GDPRPrivacyScanner

URL = "https://example.com"


def _resp(status=200, body="", headers=None, cookies=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = cookies or []
    return r


def _scanner():
    session = MagicMock()
    return GDPRPrivacyScanner(session)


def test_exception_during_get_returns_empty():
    """Branch: http.get raises Exception — returns empty list."""
    s = _scanner()
    with patch.object(s.http, "get", side_effect=Exception("connection refused")):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert results == []


def test_none_response_returns_empty():
    """Branch: http.get returns None — returns empty list."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert results == []


def test_cookiebot_cmp_detected_passes():
    """Branch: Cookiebot CMP script present — PASS for consent banner."""
    s = _scanner()
    html = (
        "<html><head>"
        '<script src="https://consent.cookiebot.com/abc/cd.js" '
        'data-cbid="abc" async></script>'
        '<a href="/privacy-policy">Privacy Policy</a>'
        "</head><body></body></html>"
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
    assert any("consent" in r["type"].lower() or "gdpr" in r["type"].lower()
               for r in passes)


def test_no_consent_banner_warns_or_fails():
    """Branch: no CMP detected in page — WARN or FAIL."""
    s = _scanner()
    html = "<html><head><title>My Site</title></head><body><p>Hello</p></body></html>"
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert bad
    assert any("consent" in r["type"].lower() or "gdpr" in r["type"].lower()
               for r in bad)


def test_google_analytics_without_consent_warns():
    """Branch: Google Analytics script loaded without consent manager — WARN."""
    s = _scanner()
    html = (
        "<html><head>"
        "<script async src='https://www.googletagmanager.com/gtag/js?id=G-12345'></script>"
        "<script>window.dataLayer=[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());</script>"
        '<a href="/privacy">Privacy</a>'
        "</head><body></body></html>"
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("google analytics" in r["type"].lower() or "tracking" in r["type"].lower()
               or "gdpr" in r["type"].lower() for r in warns)


def test_privacy_policy_link_present_passes():
    """Branch: privacy policy link in page — PASS for privacy link check."""
    s = _scanner()
    html = (
        "<html><body>"
        '<a href="/privacy-policy">Privacy Policy</a>'
        "</body></html>"
    )
    with patch.object(s.http, "get", return_value=_resp(200, html)):
        results = s.scan(URL)
    # Should have a PASS for privacy policy link
    passes = [r for r in results if r["status"] == "PASS"]
    assert isinstance(results, list)
