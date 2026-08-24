"""Tests for tblue.scanner.saml — SAMLScanner."""

import pytest
from unittest.mock import MagicMock, patch

from tblue.scanner.saml import SAMLScanner

URL = "https://example.com"


def _make_scanner():
    session = MagicMock()
    return SAMLScanner(session)


def _mock_resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


# ── No response ────────────────────────────────────────────────────────────────

def test_scan_none_response():
    scanner = _make_scanner()
    with patch.object(scanner.http, "get", return_value=None):
        results = scanner.scan(URL)
    assert results == []


# ── No SAML detected → PASS ───────────────────────────────────────────────────

def test_scan_no_saml():
    scanner = _make_scanner()
    body = "<html><body>Normal page</body></html>"
    with patch.object(scanner.http, "get", return_value=_mock_resp(404)):
        # Get page returns None (simulate by always 404)
        results = scanner.scan(URL)
    # All probes 404, page body 404 → PASS
    assert any(r["status"] == "PASS" for r in results)


def test_scan_page_no_saml_indicators():
    scanner = _make_scanner()
    body = "<html><body><form action='/login'><input name='user'></form></body></html>"

    def side_effect(url, allow_redirects=True, headers=None, **kwargs):
        if url == URL:
            return _mock_resp(200, body)
        return _mock_resp(404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


# ── HTTP SAML endpoint → FAIL ─────────────────────────────────────────────────

def test_scan_http_saml_in_page():
    scanner = _make_scanner()
    # Must have a SAML indicator to trigger detection, plus an HTTP SAML URL
    body = (
        '<html><a href="http://idp.example.com/sso">Login</a>'
        '<input name="SAMLRequest" value="test"></html>'
    )

    def side_effect(url, allow_redirects=True, headers=None, **kwargs):
        if url == URL:
            return _mock_resp(200, body)
        return _mock_resp(404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("HTTP" in f["type"] for f in fails)


# ── Open RelayState → FAIL ────────────────────────────────────────────────────

def test_scan_open_relay_state():
    scanner = _make_scanner()
    body = '<html><a href="/sso?SAMLRequest=abc&RelayState=http://evil.com">SSO</a></html>'

    def side_effect(url, allow_redirects=True, headers=None, **kwargs):
        if url == URL:
            return _mock_resp(200, body)
        return _mock_resp(404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("RelayState" in f["type"] for f in fails)


def test_scan_internal_relay_state_no_fail():
    scanner = _make_scanner()
    # RelayState is a relative path, not an external URL
    body = '<html><a href="/saml/sso?SAMLRequest=base64data&RelayState=/dashboard">SSO</a></html>'

    def side_effect(url, allow_redirects=True, headers=None, **kwargs):
        if url == URL:
            return _mock_resp(200, body)
        return _mock_resp(404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL" and "RelayState" in r["type"]]
    assert not fails


# ── SAML assertion in page source → WARN ─────────────────────────────────────

def test_scan_saml_assertion_in_page():
    scanner = _make_scanner()
    # Use SAMLResponse=<base64> pattern that the regex matches
    long_b64 = "A" * 120
    body = f'<html><body>SAMLResponse={long_b64}</body></html>'

    def side_effect(url, allow_redirects=True, headers=None, **kwargs):
        if url == URL:
            return _mock_resp(200, body)
        return _mock_resp(404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("assertion" in w["type"].lower() for w in warns)


# ── SAML metadata exposed → WARN ─────────────────────────────────────────────

def test_scan_metadata_exposed():
    scanner = _make_scanner()
    body = "<html><body>Normal page</body></html>"

    def side_effect(url, allow_redirects=True, headers=None, **kwargs):
        if url == URL:
            return _mock_resp(200, body)
        if "metadata" in url:
            return _mock_resp(200, "<EntityDescriptor>...</EntityDescriptor>")
        return _mock_resp(404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("metadata" in w["type"].lower() for w in warns)


# ── SAML/SSO endpoint reachable → WARN ───────────────────────────────────────

def test_scan_sso_endpoint_found():
    scanner = _make_scanner()
    body = "<html><body>Normal page</body></html>"

    def side_effect(url, allow_redirects=True, headers=None, **kwargs):
        if url == URL:
            return _mock_resp(200, body)
        if url.endswith("/saml/login"):
            return _mock_resp(200, "<html>SAML Login</html>")
        return _mock_resp(404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


# ── No issues with SAML detected → PASS ──────────────────────────────────────

def test_scan_saml_no_issues():
    scanner = _make_scanner()
    # SAML indicator in page but no bad patterns
    body = '<html><a href="/authorize?SAMLRequest=test&state=secure">Login</a></html>'

    def side_effect(url, allow_redirects=True, headers=None, **kwargs):
        if url == URL:
            return _mock_resp(200, body)
        return _mock_resp(404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    # Should find SAML but have no FAIL
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not fails


# ── Exception in probe ────────────────────────────────────────────────────────

def test_scan_probe_exception():
    scanner = _make_scanner()
    body = "<html><a href='/saml/sso?SAMLRequest=test'>SSO</a></html>"

    call_count = {"n": 0}

    def side_effect(url, allow_redirects=True, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return _mock_resp(200, body)
        raise ConnectionError("timeout")

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    # Should not crash
    assert results is not None
