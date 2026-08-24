"""Tests for tblue.scanner.jwt_advanced — Advanced JWT security scanner."""

import json
import base64
import time
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.jwt_advanced import JWTAdvancedScanner, _analyze_jwt, _b64_decode_jwt_part


def _scanner():
    session = MagicMock()
    return JWTAdvancedScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {"content-type": "text/html"}
    r.cookies = {}
    return r


def _make_jwt(header: dict, payload: dict, sig: str = "fakesig") -> str:
    """Build a fake JWT (not cryptographically valid — tests decode/analysis only)."""
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64(header)}.{b64(payload)}.{sig}"


# ── _b64_decode_jwt_part ──────────────────────────────────────────────────────

def test_decode_valid_header():
    token = _make_jwt({"alg": "RS256", "typ": "JWT"}, {"sub": "1234"})
    header = _b64_decode_jwt_part(token.split(".")[0])
    assert header["alg"] == "RS256"

def test_decode_invalid_returns_none():
    result = _b64_decode_jwt_part("not_base64!!!")
    assert result is None


# ── _analyze_jwt ──────────────────────────────────────────────────────────────

def test_alg_none_fail():
    token = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "1"})
    issues = _analyze_jwt(token, "https://x.com")
    assert any("none" in i["type"].lower() for i in issues)
    assert any(i["status"] == "FAIL" for i in issues)

def test_kid_path_traversal_fail():
    token = _make_jwt({"alg": "HS256", "kid": "../../etc/passwd"}, {"sub": "1", "exp": 9999999999})
    issues = _analyze_jwt(token, "https://x.com")
    assert any("kid" in i["type"].lower() or "path" in i["type"].lower() for i in issues)
    assert any(i["status"] == "FAIL" for i in issues)

def test_jku_over_http_fail():
    token = _make_jwt(
        {"alg": "RS256", "jku": "http://attacker.com/.well-known/jwks.json"},
        {"sub": "1", "exp": 9999999999, "iss": "auth.example.com"}
    )
    issues = _analyze_jwt(token, "https://example.com")
    assert any("jku" in i["type"].lower() or "http" in i["type"].lower() for i in issues)
    assert any(i["status"] == "FAIL" for i in issues)

def test_jku_external_domain_warn():
    token = _make_jwt(
        {"alg": "RS256", "jku": "https://attacker.com/.well-known/jwks.json"},
        {"sub": "1", "exp": 9999999999, "iss": "auth.example.com"}
    )
    issues = _analyze_jwt(token, "https://example.com")
    assert any("external" in i["type"].lower() or "jku" in i["type"].lower() for i in issues)

def test_missing_exp_fail():
    token = _make_jwt({"alg": "RS256"}, {"sub": "1", "iss": "auth"})
    issues = _analyze_jwt(token, "https://x.com")
    assert any("exp" in i["type"].lower() for i in issues)
    assert any(i["status"] == "FAIL" for i in issues)

def test_very_long_expiry_warn():
    far_future = int(time.time()) + 86400 * 30  # 30 days
    token = _make_jwt({"alg": "RS256"}, {"sub": "1", "iss": "auth", "exp": far_future})
    issues = _analyze_jwt(token, "https://x.com")
    assert any("expiry" in i["type"].lower() or "exp" in i["type"].lower() for i in issues)

def test_missing_iss_warn():
    token = _make_jwt({"alg": "RS256"}, {"sub": "1", "exp": 9999999999})
    issues = _analyze_jwt(token, "https://x.com")
    assert any("iss" in i["type"].lower() for i in issues)

def test_sensitive_payload_warn():
    token = _make_jwt(
        {"alg": "RS256"},
        {"sub": "1", "exp": 9999999999, "iss": "auth", "password": "secret123"}
    )
    issues = _analyze_jwt(token, "https://x.com")
    assert any("sensitive" in i["type"].lower() for i in issues)

def test_good_jwt_no_issues():
    exp = int(time.time()) + 900  # 15 minutes
    token = _make_jwt(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": "1", "iss": "auth.example.com", "aud": "api.example.com", "exp": exp}
    )
    issues = _analyze_jwt(token, "https://example.com")
    assert not issues  # No issues for a well-formed token


# ── Scanner integration ───────────────────────────────────────────────────────

def test_no_jwt_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html>Hello</html>")):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)

def test_jwt_in_url_fail():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        results = s.scan("https://example.com?token=eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("URL" in r["type"] for r in fails)

def test_alg_none_in_page_fail():
    s = _scanner()
    token = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "user1"})
    body = f'<script>var token = "{token}";</script>'
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("none" in r["type"].lower() for r in fails)

def test_no_response():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)

def test_bearer_realm_http_warn():
    s = _scanner()
    headers = {
        "content-type": "application/json",
        "www-authenticate": 'Bearer realm="http://auth.example.com/token"',
    }
    with patch.object(s.http, "get", return_value=_resp(401, "", headers)):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("HTTP" in r["type"] or "realm" in r["type"].lower() for r in warns)
