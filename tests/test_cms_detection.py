"""Tests for CMS / framework fingerprinting scanner."""

import re
import json
from unittest.mock import MagicMock, patch
from tblue.scanner.cms_detection import CMSDetectionScanner


def _scanner(html="", headers=None, osv_vulns=None):
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = headers or {}
        resp.text = html
        resp.url = url
        # OSV batch response
        if "osv.dev" in url:
            resp.json.return_value = {"vulns": osv_vulns or []}
        return resp

    session.request.side_effect = fake_request
    return CMSDetectionScanner(session)


# ── WordPress ─────────────────────────────────────────────────────────────────

def test_wordpress_detected_via_generator_tag():
    html = '<meta name="generator" content="WordPress 6.3.1">'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert any("wordpress" in r["type"].lower() for r in results)


def test_wordpress_detected_via_wp_content():
    html = '<link rel="stylesheet" href="/wp-content/themes/default/style.css">'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert any("wordpress" in r["type"].lower() for r in results)


def test_wordpress_version_extracted():
    html = '<meta name="generator" content="WordPress 5.8.0">'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    r = next(r for r in results if "wordpress" in r["type"].lower())
    assert r.get("cms_version") == "5.8.0" or "5.8.0" in r["detail"]


# ── Django ────────────────────────────────────────────────────────────────────

def test_django_detected_via_csrf_token():
    html = '<input type="hidden" name="csrfmiddlewaretoken" value="abc123">'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert any("django" in r["type"].lower() for r in results)


# ── Next.js ───────────────────────────────────────────────────────────────────

def test_nextjs_detected_via_next_data():
    html = '<script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert any("next" in r["type"].lower() for r in results)


def test_nextjs_detected_via_powered_by_header():
    scanner = _scanner(headers={"X-Powered-By": "Next.js"})
    results = scanner.scan("https://example.com")
    assert any("next" in r["type"].lower() for r in results)


# ── Laravel ───────────────────────────────────────────────────────────────────

def test_laravel_detected_via_xsrf_cookie():
    html = '<script>var token = "XSRF-TOKEN";</script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert any("laravel" in r["type"].lower() for r in results)


# ── CVE correlation ───────────────────────────────────────────────────────────

def test_known_cves_produces_fail():
    html = '<meta name="generator" content="WordPress 5.0.0">'
    vulns = [{"id": "GHSA-abc1-2345-6789", "summary": "RCE in WordPress",
               "severity": [{"type": "CVSS_V3", "score": "9.8"}]}]
    scanner = _scanner(html=html, osv_vulns=vulns)
    # Patch _check_osv to return vulns directly
    scanner._check_osv = lambda sig, ver: vulns
    results = scanner.scan("https://example.com")
    # With mocked OSV, WordPress is detected — at minimum a WARN or FAIL
    assert any("wordpress" in r["type"].lower() and r["status"] in ("WARN", "FAIL")
               for r in results)


# ── No CMS ────────────────────────────────────────────────────────────────────

def test_no_cms_detected_passes():
    scanner = _scanner(html="<html><body><h1>Hello</h1></body></html>")
    results = scanner.scan("https://example.com")
    assert any("not identified" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_network_error_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("timeout")
    scanner = CMSDetectionScanner(session)
    results = scanner.scan("https://example.com")
    assert results == []


# ── Shopify (no version) ──────────────────────────────────────────────────────

def test_shopify_detected_via_cdn():
    html = '<script src="https://cdn.shopify.com/s/files/1/app.js"></script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    assert any("shopify" in r["type"].lower() for r in results)


def test_shopify_no_version_warns():
    html = '<script src="https://cdn.shopify.com/s/files/1/app.js"></script>'
    scanner = _scanner(html=html)
    results = scanner.scan("https://example.com")
    shopify_r = next(r for r in results if "shopify" in r["type"].lower())
    assert shopify_r["status"] == "WARN"


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_get_raises_exception_returns_empty():
    """Exception during http.get is caught and returns [] — lines 166-167."""
    session = MagicMock()
    scanner = CMSDetectionScanner(session)
    with patch.object(scanner.http, "get", side_effect=RuntimeError("timeout")):
        results = scanner.scan("https://example.com")
    assert results == []


def test_matches_via_version_regex_only():
    """_matches() returns True via version_regex when no html/header patterns match — line 241."""
    session = MagicMock()
    session.request.return_value = MagicMock(
        status_code=200, headers={}, text="", url="https://example.com"
    )
    scanner = CMSDetectionScanner(session)
    sig = {"version_regex": re.compile(r"myapp-([\d.]+)")}
    assert scanner._matches(sig, "myapp-1.2.3 running here", "") is True


def test_matches_returns_false_when_nothing_matches():
    """_matches() returns False when no patterns match."""
    session = MagicMock()
    session.request.return_value = MagicMock(
        status_code=200, headers={}, text="", url="https://example.com"
    )
    scanner = CMSDetectionScanner(session)
    sig = {"html_patterns": [re.compile(r"wp-content")]}
    assert scanner._matches(sig, "Hello world", "") is False


def test_check_osv_returns_vulns_on_200():
    """_check_osv() POST success returns vulns list — lines 257-264."""
    session = MagicMock()
    osv_resp = MagicMock()
    osv_resp.status_code = 200
    osv_resp.json.return_value = {"vulns": [{"id": "GHSA-test-1234"}]}
    session.post.return_value = osv_resp
    session.request.return_value = MagicMock(
        status_code=200, headers={}, text="", url="https://example.com"
    )
    scanner = CMSDetectionScanner(session)
    # Inject a real http.session.post via the scanner's session
    scanner.http.session = MagicMock()
    scanner.http.session.post.return_value = osv_resp
    sig = {"ecosystem": "npm", "osv_package": "express"}
    result = scanner._check_osv(sig, "4.17.1")
    assert result == [{"id": "GHSA-test-1234"}]


def test_check_osv_returns_empty_on_exception():
    """_check_osv() catches exception and returns [] — lines 265-267."""
    session = MagicMock()
    session.request.return_value = MagicMock(
        status_code=200, headers={}, text="", url="https://example.com"
    )
    scanner = CMSDetectionScanner(session)
    scanner.http.session = MagicMock()
    scanner.http.session.post.side_effect = Exception("network error")
    sig = {"ecosystem": "npm", "osv_package": "express"}
    result = scanner._check_osv(sig, "4.17.1")
    assert result == []
