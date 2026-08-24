"""
Tests for information disclosure scanner.
"""

import pytest
from unittest.mock import MagicMock, call, patch
from tblue.scanner.info_disclosure import InfoDisclosureScanner


def make_scanner(
    headers: dict,
    html: str = "<html><body></body></html>",
    status_code: int = 404,  # 404 by default so path probes don't false-positive
) -> InfoDisclosureScanner:
    session            = MagicMock()
    resp               = MagicMock()
    resp.headers       = headers
    resp.text          = html
    resp.status_code   = status_code
    resp.url           = "https://example.com"
    session.request.return_value = resp
    return InfoDisclosureScanner(session)


# Names of the response-header disclosure checks
_HEADER_DISCLOSURE_NAMES = {
    "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "Server", "X-Generator", "X-Drupal-Cache", "X-Runtime", "X-Version",
}


# ─── Header checks ────────────────────────────────────────────────────────────

def test_x_powered_by_fails():
    scanner = make_scanner({"x-powered-by": "PHP/7.2.0"})
    results = scanner.scan("https://example.com")
    assert any("X-Powered-By" in r["type"] and r["status"] == "FAIL" for r in results)


def test_server_header_with_version_fails():
    scanner = make_scanner({"server": "Apache/2.4.1 (Unix)"})
    results = scanner.scan("https://example.com")
    assert any("Server" in r["type"] and r["status"] in ("FAIL", "WARN") for r in results)


def test_server_header_generic_warns():
    scanner = make_scanner({"server": "Apache"})
    results = scanner.scan("https://example.com")
    server = next(r for r in results if "Server" in r["type"] and "meta" not in r["type"].lower() and "comment" not in r["type"].lower())
    assert server["status"] == "WARN"


def test_no_disclosure_headers_passes():
    scanner = make_scanner({})
    results = scanner.scan("https://example.com")
    header_results = [
        r for r in results
        if any(f"— {name}" in r["type"] for name in _HEADER_DISCLOSURE_NAMES)
    ]
    assert all(r["status"] == "PASS" for r in header_results)


def test_aspnet_version_fails():
    scanner = make_scanner({"x-aspnet-version": "4.0.30319"})
    results = scanner.scan("https://example.com")
    assert any("AspNet" in r["type"] and r["status"] == "FAIL" for r in results)


def test_x_generator_warns():
    scanner = make_scanner({"x-generator": "WordPress"})
    results = scanner.scan("https://example.com")
    assert any("Generator" in r["type"] and r["status"] in ("WARN", "FAIL") for r in results)


def test_result_contains_fix_guidance():
    scanner = make_scanner({"x-powered-by": "PHP/8.0"})
    results = scanner.scan("https://example.com")
    fail = next(r for r in results if r["status"] == "FAIL")
    assert "Fix:" in fail["detail"]


def test_result_contains_current_value():
    scanner = make_scanner({"x-powered-by": "PHP/8.0"})
    results = scanner.scan("https://example.com")
    fail = next(r for r in results if r["status"] == "FAIL")
    assert "PHP/8.0" in fail["detail"]


def test_failed_request_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("Timeout")
    scanner = InfoDisclosureScanner(session, retries=1)
    results = scanner.scan("https://example.com")
    assert results == []


def test_multiple_disclosure_headers():
    scanner = make_scanner({
        "x-powered-by": "PHP/7.2",
        "server":        "Apache/2.4",
        "x-generator":  "Drupal 8",
    })
    results = scanner.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert len(fails) >= 2


# ─── Meta tag checks ──────────────────────────────────────────────────────────

def test_meta_generator_warns():
    html = '<html><head><meta name="generator" content="WordPress 6.0"></head><body></body></html>'
    scanner = make_scanner({}, html)
    results = scanner.scan("https://example.com")
    assert any("meta generator" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_no_meta_generator_passes():
    html = "<html><head><title>Test</title></head><body></body></html>"
    scanner = make_scanner({}, html)
    results = scanner.scan("https://example.com")
    assert any("meta generator" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ─── HTML comment checks ──────────────────────────────────────────────────────

def test_sensitive_comment_warns():
    html = "<html><body><!-- TODO: remove debug password here --></body></html>"
    scanner = make_scanner({}, html)
    results = scanner.scan("https://example.com")
    assert any("comment" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_normal_comment_passes():
    html = "<html><body><!-- Navigation section --></body></html>"
    scanner = make_scanner({}, html)
    results = scanner.scan("https://example.com")
    assert any("comment" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_api_key_in_comment_warns():
    html = "<html><body><!-- api_key: abc123 --></body></html>"
    scanner = make_scanner({}, html)
    results = scanner.scan("https://example.com")
    assert any("comment" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ─── Internal IP disclosure ───────────────────────────────────────────────────

def test_internal_ip_in_header_warns():
    scanner = make_scanner({"via": "1.1 192.168.1.10 (proxy)"})
    results = scanner.scan("https://example.com")
    assert any("internal IP" in r["type"] and r["status"] == "WARN" for r in results)


def test_internal_ip_in_html_warns():
    html = "<html><body><!-- Debug: server 10.0.0.5 --></body></html>"
    scanner = make_scanner({}, html)
    results = scanner.scan("https://example.com")
    assert any("internal IP" in r["type"] and r["status"] == "WARN" for r in results)


def test_no_internal_ip_passes():
    scanner = make_scanner({"server": "nginx"})
    results = scanner.scan("https://example.com")
    assert any("internal IP" in r["type"] and r["status"] == "PASS" for r in results)


# ─── Email disclosure ─────────────────────────────────────────────────────────

def test_email_in_html_warns():
    html = "<html><body><a href='mailto:dev@mycompany.io'>Contact</a></body></html>"
    scanner = make_scanner({}, html)
    results = scanner.scan("https://example.com")
    assert any("email" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_public_domain_email_not_flagged():
    html = "<html><body><!-- test@example.com --></body></html>"
    scanner = make_scanner({}, html)
    results = scanner.scan("https://example.com")
    assert any("email" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ─── API key patterns ─────────────────────────────────────────────────────────

def test_aws_key_in_html_fails():
    html = "<html><body><script>var key = 'AKIAIOSFODNN7EXAMPLE';</script></body></html>"
    scanner = make_scanner({}, html)
    results = scanner.scan("https://example.com")
    assert any("API keys" in r["type"] and r["status"] == "FAIL" for r in results)


def test_no_api_key_passes():
    html = "<html><body><p>Hello world</p></body></html>"
    scanner = make_scanner({}, html)
    results = scanner.scan("https://example.com")
    assert any("API keys" in r["type"] and r["status"] == "PASS" for r in results)


# ─── Directory listing ────────────────────────────────────────────────────────

def test_directory_listing_detected():
    html = "<html><head><title>Index of /</title></head><body>Index of /</body></html>"
    scanner = make_scanner({}, html)
    results = scanner.scan("https://example.com")
    assert any("directory listing" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_no_directory_listing_passes():
    html = "<html><body><h1>Welcome</h1></body></html>"
    scanner = make_scanner({}, html)
    results = scanner.scan("https://example.com")
    assert any("directory listing" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ─── Error page stack traces ──────────────────────────────────────────────────

def test_stack_trace_in_error_page_fails():
    error_html = "<html><body>Traceback (most recent call last):\n  File app.py line 42</body></html>"
    scanner = make_scanner({}, error_html)
    results = scanner.scan("https://example.com")
    assert any("stack trace" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_clean_error_page_passes():
    error_html = "<html><body><h1>404 Not Found</h1></body></html>"
    scanner = make_scanner({}, error_html)
    results = scanner.scan("https://example.com")
    assert any("stack trace" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_empty_html_comment_is_skipped():
    """Empty comment text hits `continue` — line 286."""
    html = "<html><body><!----><p>No content</p></body></html>"
    scanner = make_scanner({}, html)
    results = scanner.scan("https://example.com")
    # Empty comment is skipped, so no WARN for comments
    comment_results = [r for r in results if "comment" in r["type"].lower()]
    assert all(r["status"] == "PASS" for r in comment_results)


def test_phone_number_in_html_warns():
    """Phone number found → PII WARN — lines 409-416."""
    html = "<html><body><p>Call us: +1 (555) 123-4567</p></body></html>"
    scanner = make_scanner({}, html)
    results = scanner.scan("https://example.com")
    assert any("pii" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_credit_card_in_html_warns():
    """Credit card pattern found → PII WARN — lines 412, 415-416."""
    html = "<html><body><p>Card: 4111 1111 1111 1111</p></body></html>"
    scanner = make_scanner({}, html)
    results = scanner.scan("https://example.com")
    assert any("pii" in r["type"].lower() and r["status"] == "WARN" for r in results)


def _make_selective_scanner(main_html, sensitive_responses=None):
    """Build a scanner with different responses per URL."""
    session = MagicMock()

    def fake_request(method, url, **kw):
        resp = MagicMock()
        resp.headers = {}
        resp.url = url
        if sensitive_responses:
            for fragment, (code, body) in sensitive_responses.items():
                if fragment in url:
                    resp.status_code = code
                    resp.text = body
                    return resp
        resp.status_code = 404
        resp.text = main_html
        return resp

    session.request.side_effect = fake_request
    return InfoDisclosureScanner(session)


def test_source_map_accessible_warns():
    """Source map with 200 + 'sources' → WARN — lines 442-449."""
    html = '<html><body><script src="/app.js"></script></body></html>'
    scanner = _make_selective_scanner(
        html,
        {"/app.js.map": (200, '{"sources":["src/index.js"],"mappings":""}')},
    )
    results = scanner.scan("https://example.com")
    assert any("source map" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_sensitive_path_200_flagged():
    """Sensitive path returning 200 → FAIL — lines 477-478."""
    scanner = _make_selective_scanner(
        "<html></html>",
        {"/.git/config": (200, "[core]\n\trepositoryformatversion = 0\n")},
    )
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "FAIL" and ".git" in r.get("url", "") for r in results)


def test_sensitive_path_403_warns():
    """Sensitive path returning 403 → WARN — lines 486-487."""
    scanner = _make_selective_scanner(
        "<html></html>",
        {"/.env": (403, "Forbidden")},
    )
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "WARN" and ".env" in r.get("url", "") for r in results)


def test_sensitive_path_none_response_skipped():
    """None response from http.get is skipped without crashing — line 474."""
    session = MagicMock()

    def fake_request(method, url, **kw):
        if "/.git" in url or "/.env" in url or "/backup" in url:
            return None
        resp = MagicMock()
        resp.status_code = 404
        resp.headers = {}
        resp.text = "<html></html>"
        resp.url = url
        return resp

    session.request.side_effect = fake_request
    scanner = InfoDisclosureScanner(session)
    results = scanner.scan("https://example.com")
    # Just must not crash
    assert isinstance(results, list)


def test_error_page_none_response_returns_early():
    """None response from error page probe causes early return — line 503."""
    session = MagicMock()
    call_num = {"n": 0}

    def fake_request(method, url, **kw):
        call_num["n"] += 1
        if "nonexistent-path-probe" in url:
            return None
        resp = MagicMock()
        resp.status_code = 404
        resp.headers = {}
        resp.text = "<html></html>"
        resp.url = url
        return resp

    session.request.side_effect = fake_request
    scanner = InfoDisclosureScanner(session)
    results = scanner.scan("https://example.com")
    assert isinstance(results, list)
