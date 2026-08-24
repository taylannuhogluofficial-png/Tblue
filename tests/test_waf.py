"""
Tests for WAF/CDN detection scanner.
"""

import pytest
from unittest.mock import MagicMock
from tblue.scanner.waf import WAFScanner


def make_scanner(headers: dict = None, cookies: list = None) -> WAFScanner:
    session = MagicMock()
    resp    = MagicMock()
    resp.status_code = 200
    resp.url         = "https://example.com"
    resp.headers     = headers or {}
    resp.raw         = MagicMock()
    resp.raw.headers = MagicMock()
    resp.raw.headers.getlist = lambda h: (cookies or []) if h == "set-cookie" else []
    session.request.return_value = resp
    return WAFScanner(session)


# ── Provider detection ────────────────────────────────────────────────────────

def test_cloudflare_detected_via_cf_ray():
    scanner = make_scanner(headers={"cf-ray": "abc123-LHR", "server": "cloudflare"})
    results = scanner.scan("https://example.com")
    assert any("cloudflare" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_cloudflare_detected_via_server_header():
    scanner = make_scanner(headers={"server": "cloudflare"})
    results = scanner.scan("https://example.com")
    assert any("cloudflare" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_aws_cloudfront_detected():
    scanner = make_scanner(headers={"x-amz-cf-id": "abc123", "via": "1.1 amazon (CloudFront)"})
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)
    assert any("aws" in r["type"].lower() or "cloudfront" in r["type"].lower() for r in results)


def test_fastly_detected():
    scanner = make_scanner(headers={"x-fastly-request-id": "abc123"})
    results = scanner.scan("https://example.com")
    assert any("fastly" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_akamai_detected():
    scanner = make_scanner(headers={"x-akamai-request-id": "abc123"})
    results = scanner.scan("https://example.com")
    assert any("akamai" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_azure_detected():
    scanner = make_scanner(headers={"x-azure-ref": "abc123"})
    results = scanner.scan("https://example.com")
    assert any("azure" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_imperva_detected_via_cookie():
    scanner = make_scanner(cookies=["incap_ses_1234=xyz; Path=/"])
    results = scanner.scan("https://example.com")
    assert any("imperva" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_cloudflare_detected_via_cf_cookie():
    scanner = make_scanner(cookies=["__cf_bm=abc123; Path=/; HttpOnly"])
    results = scanner.scan("https://example.com")
    assert any("cloudflare" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ── No WAF ────────────────────────────────────────────────────────────────────

def test_no_waf_warns():
    scanner = make_scanner(headers={"server": "nginx/1.24.0", "content-type": "text/html"})
    results = scanner.scan("https://example.com")
    assert any("none detected" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_no_waf_result_has_fix_guidance():
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    warn    = next(r for r in results if r["status"] == "WARN")
    assert "cloudflare" in warn["detail"].lower() or "waf" in warn["detail"].lower()


# ── Error handling ────────────────────────────────────────────────────────────

def test_failed_request_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("Timeout")
    scanner = WAFScanner(session, retries=1)
    results = scanner.scan("https://example.com")
    assert results == []
