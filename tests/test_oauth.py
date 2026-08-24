"""Tests for tblue.scanner.oauth — OAuthScanner."""

import pytest
from unittest.mock import MagicMock, patch

from tblue.scanner.oauth import OAuthScanner

URL = "https://example.com"


def _make_scanner():
    session = MagicMock()
    return OAuthScanner(session)


def _mock_resp(body="", status=200):
    r = MagicMock()
    r.text = body
    r.status_code = status
    return r


# ── No OAuth detected ────────────────────────────────────────────────────────

def test_scan_no_oauth_on_page():
    scanner = _make_scanner()
    body = "<html><form><input name='email'><input name='pass'></form></html>"
    none_resp = _mock_resp(status=404)

    def side_effect(url, **kwargs):
        if "well-known" in url:
            return none_resp
        return _mock_resp(body)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_scan_none_response():
    scanner = _make_scanner()
    with patch.object(scanner.http, "get", return_value=None):
        results = scanner.scan(URL)
    assert results == []


# ── Implicit flow ─────────────────────────────────────────────────────────────

def test_scan_implicit_flow_detected():
    scanner = _make_scanner()
    body = '<html><a href="/authorize?client_id=abc&response_type=token&state=xyz">Login</a></html>'
    none_resp = _mock_resp(status=404)

    def side_effect(url, **kwargs):
        if "well-known" in url:
            return none_resp
        return _mock_resp(body)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("implicit" in f["type"] for f in fails)


def test_scan_implicit_id_token():
    scanner = _make_scanner()
    body = '<html><a href="/oidc/authorize?client_id=x&response_type=id_token">Login</a></html>'
    none_resp = _mock_resp(status=404)

    def side_effect(url, **kwargs):
        if "well-known" in url:
            return none_resp
        return _mock_resp(body)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    assert any("implicit" in r["type"] for r in results)


# ── Missing state parameter ───────────────────────────────────────────────────

def test_scan_missing_state():
    scanner = _make_scanner()
    # OAuth URL with client_id but no state
    body = '<html><a href="/oauth2/authorize?client_id=abc&response_type=code">Login</a></html>'
    none_resp = _mock_resp(status=404)

    def side_effect(url, **kwargs):
        if "well-known" in url:
            return none_resp
        return _mock_resp(body)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("state" in w["type"] for w in warns)


def test_scan_state_present_no_warn():
    scanner = _make_scanner()
    body = '<html><a href="/oauth2/authorize?client_id=abc&response_type=code&state=XYZRANDOM">Login</a></html>'
    none_resp = _mock_resp(status=404)

    def side_effect(url, **kwargs):
        if "well-known" in url:
            return none_resp
        return _mock_resp(body)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    # No state-missing warning
    assert not any("state" in r["type"] for r in results)


# ── Token in URL fragment ─────────────────────────────────────────────────────

def test_scan_token_in_fragment():
    scanner = _make_scanner()
    # Include an OAuth indicator so the scanner enters the OAuth analysis path
    body = '<html><a href="/oauth/authorize?client_id=app&response_type=code&state=S">Login</a></html>'
    # Also include a fragment token (as if the page received one in the URL and has it in source)
    body_with_fragment = body + "\n<!-- callback: /cb#access_token=eyJhbGc -->"
    none_resp = _mock_resp(status=404)

    def side_effect(url, **kwargs):
        if "well-known" in url:
            return none_resp
        return _mock_resp(body_with_fragment)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("fragment" in w["type"] for w in warns)


# ── Open redirect_uri ─────────────────────────────────────────────────────────

def test_scan_localhost_redirect_uri():
    scanner = _make_scanner()
    body = '<html><a href="/oauth/authorize?client_id=x&redirect_uri=http://localhost:3000/cb&response_type=code">Login</a></html>'
    none_resp = _mock_resp(status=404)

    def side_effect(url, **kwargs):
        if "well-known" in url:
            return none_resp
        return _mock_resp(body)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("localhost redirect" in f["type"] for f in fails)


# ── Hardcoded client_secret ───────────────────────────────────────────────────

def test_scan_hardcoded_client_secret():
    scanner = _make_scanner()
    body = '<html><script>var client_secret = "abcdef1234567890abcdef12";</script></html>'
    # Also include oauth indicator
    body += '<a href="/oauth/authorize?client_id=myapp">Login</a>'
    none_resp = _mock_resp(status=404)

    def side_effect(url, **kwargs):
        if "well-known" in url:
            return none_resp
        return _mock_resp(body)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("client_secret" in f["type"] for f in fails)


# ── OIDC discovery endpoint ───────────────────────────────────────────────────

def test_scan_oidc_discovery_exposed():
    scanner = _make_scanner()
    page_body = "<html>Normal page</html>"
    oidc_body = '{"issuer":"https://example.com","authorization_endpoint":"https://example.com/authorize"}'

    def side_effect(url, **kwargs):
        if "well-known" in url:
            return _mock_resp(oidc_body, status=200)
        return _mock_resp(page_body)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("discovery" in w["type"] for w in warns)


def test_scan_oidc_discovery_not_found():
    scanner = _make_scanner()
    page_body = "<html>Normal page</html>"
    none_resp = _mock_resp(status=404)

    def side_effect(url, **kwargs):
        if "well-known" in url:
            return none_resp
        return _mock_resp(page_body)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    # No OIDC discovery warning
    assert not any("discovery" in r["type"] for r in results)


def test_scan_oidc_discovery_exception():
    scanner = _make_scanner()
    page_body = "<html>Normal page</html>"

    def side_effect(url, **kwargs):
        if "well-known" in url:
            raise ConnectionError("timeout")
        return _mock_resp(page_body)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        # Should not crash
        results = scanner.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


# ── No issues found (PASS) ───────────────────────────────────────────────────

def test_scan_oauth_flow_no_issues():
    scanner = _make_scanner()
    # Auth code flow with state — all good
    body = '<html><a href="/oauth2/authorize?client_id=abc&response_type=code&state=RAND123">Login</a></html>'
    none_resp = _mock_resp(status=404)

    def side_effect(url, **kwargs):
        if "well-known" in url:
            return none_resp
        return _mock_resp(body)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    # Should find the state present, no FAIL
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not fails
