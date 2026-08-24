"""
Tests for JWT security scanner.
"""

import json
import base64
import time
import pytest
from unittest.mock import MagicMock
from tblue.scanner.jwt_security import JWTScanner, _decode_header, _decode_payload, _get_all


def _make_jwt(header: dict, payload: dict, signature: str = "fakesig") -> str:
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64(header)}.{b64(payload)}.{signature}"


def make_scanner(body: str = "", cookie: str = "", status: int = 200) -> JWTScanner:
    session = MagicMock()
    resp    = MagicMock()
    resp.status_code = status
    resp.text        = body
    resp.url         = "https://example.com"
    resp.headers     = {}
    if cookie:
        resp.headers["set-cookie"] = cookie
    # Make raw.headers.getlist return the cookie list
    resp.raw         = MagicMock()
    resp.raw.headers = MagicMock()
    resp.raw.headers.getlist = lambda h: [cookie] if cookie and h == "set-cookie" else []
    session.request.return_value = resp
    return JWTScanner(session)


_JWT_RS256 = _make_jwt(
    {"alg": "RS256", "typ": "JWT"},
    {"sub": "1234", "exp": int(time.time()) + 600}
)
_JWT_NONE = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "1234", "exp": int(time.time()) + 600})
_JWT_HS256 = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1234", "exp": int(time.time()) + 600})
_JWT_NO_EXP = _make_jwt({"alg": "RS256", "typ": "JWT"}, {"sub": "1234"})
_JWT_LONG_EXP = _make_jwt(
    {"alg": "RS256", "typ": "JWT"},
    {"sub": "1234", "exp": int(time.time()) + 90_000}  # 25 hours
)


# ── alg:none ─────────────────────────────────────────────────────────────────

def test_alg_none_in_cookie_fails():
    scanner = make_scanner(cookie=f"token={_JWT_NONE}; HttpOnly; Secure")
    results = scanner.scan("https://example.com")
    assert any("alg:none" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_alg_none_in_body_fails():
    body    = f'{{"access_token": "{_JWT_NONE}"}}'
    scanner = make_scanner(body=body)
    results = scanner.scan("https://example.com")
    assert any("alg:none" in r["type"].lower() and r["status"] == "FAIL" for r in results)


# ── Weak algorithm ────────────────────────────────────────────────────────────

def test_hs256_warns():
    body    = f'{{"access_token": "{_JWT_HS256}"}}'
    scanner = make_scanner(body=body)
    results = scanner.scan("https://example.com")
    assert any("hs256" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Missing / long expiry ─────────────────────────────────────────────────────

def test_missing_exp_warns():
    body    = f'{{"access_token": "{_JWT_NO_EXP}"}}'
    scanner = make_scanner(body=body)
    results = scanner.scan("https://example.com")
    assert any("no expiry" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_long_expiry_warns():
    body    = f'{{"access_token": "{_JWT_LONG_EXP}"}}'
    scanner = make_scanner(body=body)
    results = scanner.scan("https://example.com")
    assert any("long-lived" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Good JWT ──────────────────────────────────────────────────────────────────

def test_strong_algorithm_short_expiry_passes():
    body    = f'{{"access_token": "{_JWT_RS256}"}}'
    scanner = make_scanner(body=body)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] == "FAIL" for r in results)


# ── No JWT ────────────────────────────────────────────────────────────────────

def test_no_jwt_in_response_passes():
    scanner = make_scanner(body='{"message": "Hello World"}')
    results = scanner.scan("https://example.com")
    assert any("no tokens detected" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


# ── Failed request ────────────────────────────────────────────────────────────

def test_failed_request_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("Timeout")
    scanner = JWTScanner(session, retries=1)
    results = scanner.scan("https://example.com")
    assert results == []


# ── Detail quality ────────────────────────────────────────────────────────────

def test_alg_none_result_has_fix_guidance():
    body    = f'{{"access_token": "{_JWT_NONE}"}}'
    scanner = make_scanner(body=body)
    results = scanner.scan("https://example.com")
    fail    = next(r for r in results if r["status"] == "FAIL")
    assert "fix" in fail["detail"].lower()
    assert "unsigned" in fail["detail"].lower() or "none" in fail["detail"].lower()


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_malformed_jwt_header_is_skipped():
    """Token matching JWT regex but header not valid JSON → _decode_header None → continue — line 61."""
    # eyJhYWFh decodes to bytes starting with '{' but not valid JSON (no closing brace)
    fake_token = "eyJhYWFh.eyJhYWFh.fakesig"
    body = f"raw token: {fake_token}"
    scanner = make_scanner(body=body)
    results = scanner.scan("https://example.com")
    # Token is skipped; scanner should not crash
    assert isinstance(results, list)


def test_jwt_in_authorization_header():
    """JWT found in Authorization response header — line 101."""
    session = MagicMock()
    resp    = MagicMock()
    resp.status_code = 200
    resp.url = "https://example.com"
    resp.text = ""
    resp.headers = {"authorization": f"Bearer {_JWT_NONE}"}
    resp.raw = MagicMock()
    resp.raw.headers = MagicMock()
    resp.raw.headers.getlist = lambda h: []
    session.request.return_value = resp
    scanner = JWTScanner(session)
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "FAIL" for r in results)


def test_jwt_in_raw_body_text():
    """JWT in body not in a named key is picked up by full-text scan — line 112."""
    # Body has a JWT directly, not inside {"access_token": ...}
    body = f"Here is your token: {_JWT_HS256} use it wisely"
    scanner = make_scanner(body=body)
    results = scanner.scan("https://example.com")
    # HS256 should be detected from body raw scan
    assert any(r["status"] in ("WARN", "FAIL") for r in results)


def test_decode_header_returns_none_on_bad_input():
    """_decode_header() returns None for undecodable input — lines 188-189."""
    result = _decode_header("garbage.notbase64.sig")
    assert result is None


def test_decode_payload_returns_none_on_bad_input():
    """_decode_payload() returns None for undecodable payload — lines 197-198."""
    result = _decode_payload("header.notbase64json.sig")
    assert result is None


def test_get_all_uses_raw_getlist():
    """_get_all() uses raw.headers.getlist when available — lines 206-209."""
    resp = MagicMock()
    resp.raw = MagicMock()
    resp.raw.headers = MagicMock()
    resp.raw.headers.getlist = lambda h: ["cookie1=val1", "cookie2=val2"]
    resp.headers = {}
    result = _get_all(resp, "set-cookie")
    assert result == ["cookie1=val1", "cookie2=val2"]


def test_get_all_falls_back_to_headers_dict():
    """_get_all() falls back to resp.headers when raw raises — line 208-209."""
    resp = MagicMock()
    resp.raw = MagicMock()
    resp.raw.headers = MagicMock()
    resp.raw.headers.getlist.side_effect = AttributeError("no getlist")
    resp.headers = {"set-cookie": "session=abc; HttpOnly"}
    result = _get_all(resp, "set-cookie")
    assert result == ["session=abc; HttpOnly"]
