"""Tests for tblue.scanner.oauth_advanced — OAuth 2.0 advanced security scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.oauth_advanced import OAuthAdvancedScanner


def _scanner():
    session = MagicMock()
    return OAuthAdvancedScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


# ── None response → PASS ──────────────────────────────────────────────────────

def test_no_response_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


# ── No OAuth flows → PASS ─────────────────────────────────────────────────────

def test_no_oauth_pass():
    s = _scanner()
    plain_html = "<html><body><h1>Home</h1></body></html>"
    with patch.object(s.http, "get", return_value=_resp(200, plain_html)):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


# ── Auth Code flow without PKCE → WARN ───────────────────────────────────────

def test_auth_code_without_pkce_warns():
    s = _scanner()
    html = ('<html><body>'
            '<a href="/authorize?response_type=code&client_id=abc&state=xyz">Login</a>'
            '</body></html>')

    def get_side_effect(url, **kwargs):
        if "openid-configuration" in url or "oauth-authorization-server" in url:
            return _resp(404, "")
        if "/oauth/register" in url or "/connect/register" in url:
            return _resp(404, "")
        return _resp(200, html)

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("pkce" in r["type"].lower() for r in warns)


# ── PKCE plain method → WARN ──────────────────────────────────────────────────

def test_pkce_plain_method_warns():
    s = _scanner()
    html = ('<html><body>'
            '<a href="/authorize?response_type=code&client_id=abc&state=xyz'
            '&code_challenge=abc123&code_challenge_method=plain">Login</a>'
            '</body></html>')

    def get_side_effect(url, **kwargs):
        if "openid-configuration" in url or "oauth-authorization-server" in url:
            return _resp(404, "")
        if "/oauth/register" in url or "/connect/register" in url:
            return _resp(404, "")
        return _resp(200, html)

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("plain" in r["type"].lower() for r in warns)


# ── Over-privileged scope → WARN ──────────────────────────────────────────────

def test_overprivileged_scope_warns():
    s = _scanner()
    html = ('<html><body>'
            '<a href="/authorize?response_type=code&client_id=abc&scope=admin+profile'
            '&code_challenge=abc&code_challenge_method=S256&state=xyz">Login</a>'
            '</body></html>')

    def get_side_effect(url, **kwargs):
        if "openid-configuration" in url or "oauth-authorization-server" in url:
            return _resp(404, "")
        if "/oauth/register" in url or "/connect/register" in url:
            return _resp(404, "")
        return _resp(200, html)

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("scope" in r["type"].lower() or "privileged" in r["type"].lower() for r in warns)


# ── OIDC missing nonce → WARN ─────────────────────────────────────────────────

def test_oidc_missing_nonce_warns():
    s = _scanner()
    html = ('<html><body>'
            '<a href="/authorize?response_type=code&client_id=abc&scope=openid+profile'
            '&code_challenge=abc&code_challenge_method=S256&state=xyz">Login</a>'
            '</body></html>')

    def get_side_effect(url, **kwargs):
        if "openid-configuration" in url or "oauth-authorization-server" in url:
            return _resp(404, "")
        if "/oauth/register" in url or "/connect/register" in url:
            return _resp(404, "")
        return _resp(200, html)

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("nonce" in r["type"].lower() for r in warns)


# ── Device flow endpoint in OIDC discovery → WARN ────────────────────────────

def test_device_flow_endpoint_warns():
    s = _scanner()
    html = ('<html><body>'
            '<a href="/authorize?response_type=code&client_id=abc'
            '&code_challenge=abc&code_challenge_method=S256&state=xyz">Login</a>'
            '</body></html>')
    oidc_doc = '{"issuer":"https://example.com","authorization_endpoint":"/authorize",' \
               '"device_authorization_endpoint":"https://example.com/device/code"}'

    def get_side_effect(url, **kwargs):
        if "openid-configuration" in url:
            return _resp(200, oidc_doc, {"content-type": "application/json"})
        if "oauth-authorization-server" in url:
            return _resp(404, "")
        if "/oauth/register" in url or "/connect/register" in url:
            return _resp(404, "")
        return _resp(200, html)

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("device" in r["type"].lower() for r in warns)


# ── Dynamic client registration open → WARN ──────────────────────────────────

def test_dynamic_client_registration_warns():
    s = _scanner()
    html = ('<html><body>'
            '<a href="/authorize?response_type=code&client_id=abc'
            '&code_challenge=abc&code_challenge_method=S256&state=xyz">Login</a>'
            '</body></html>')
    dcr_resp = '{"client_id":"new_client","client_secret":"secret123"}'

    def get_side_effect(url, **kwargs):
        if "openid-configuration" in url or "oauth-authorization-server" in url:
            return _resp(404, "")
        if "/oauth/register" in url:
            return _resp(200, dcr_resp, {"content-type": "application/json"})
        if "/connect/register" in url or "/api/oauth/clients" in url:
            return _resp(404, "")
        return _resp(200, html)

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("dynamic client registration" in r["type"].lower() for r in warns)


# ── Well-configured PKCE S256 flow → PASS ────────────────────────────────────

def test_good_pkce_s256_passes():
    s = _scanner()
    html = ('<html><body>'
            '<a href="/authorize?response_type=code&client_id=abc'
            '&code_challenge=abcdefghijklmnop&code_challenge_method=S256'
            '&state=securestate&nonce=securenonce&scope=openid+profile">Login</a>'
            '</body></html>')

    def get_side_effect(url, **kwargs):
        if "openid-configuration" in url or "oauth-authorization-server" in url:
            return _resp(404, "")
        if any(p in url for p in ["/oauth/register", "/connect/register",
                                   "/api/oauth/clients", "/oidc/register"]):
            return _resp(404, "")
        return _resp(200, html)

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
