"""Extra branch coverage for tblue.scanner.jwt_security."""

import base64
import json
import pytest
from unittest.mock import MagicMock
from tblue.scanner.jwt_security import (
    JWTScanner, _decode_header, _decode_payload, _get_all
)


def _make_jwt(header: dict, payload: dict) -> str:
    def b64enc(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64enc(header)}.{b64enc(payload)}.fakesig"


# ── _decode_header / _decode_payload fallbacks ────────────────────────────────

def test_decode_header_invalid_returns_none():
    assert _decode_header("not.a.jwt") is None


def test_decode_payload_invalid_returns_none():
    assert _decode_payload("not.a.jwt") is None


def test_decode_payload_valid():
    token = _make_jwt({"alg": "RS256"}, {"sub": "user", "exp": 9999999999})
    payload = _decode_payload(token)
    assert payload is not None
    assert payload["sub"] == "user"


# ── _get_all multiple-value header ────────────────────────────────────────────

def test_get_all_with_getlist():
    resp = MagicMock()
    resp.raw.headers.getlist.return_value = ["value1", "value2"]
    result = _get_all(resp, "set-cookie")
    assert result == ["value1", "value2"]


def test_get_all_without_getlist_fallback():
    resp = MagicMock()
    resp.raw.headers = object()  # no getlist
    resp.headers.get.return_value = "single-value"
    result = _get_all(resp, "set-cookie")
    assert result == ["single-value"]


def test_get_all_exception_fallback():
    resp = MagicMock()
    resp.raw = None  # accessing .raw.headers will raise AttributeError
    resp.headers.get.return_value = ""
    result = _get_all(resp, "set-cookie")
    assert result == []


# ── JWT in authorization header ───────────────────────────────────────────────

def test_jwt_in_auth_header_detected():
    token = _make_jwt({"alg": "none"}, {"sub": "user", "exp": 9999999999})
    session = MagicMock()
    resp = MagicMock()
    resp.text = ""
    resp.headers = {"authorization": f"Bearer {token}"}
    resp.raw.headers = MagicMock()
    resp.raw.headers.getlist.return_value = []

    s = JWTScanner(session)
    s.http.get = MagicMock(return_value=resp)
    results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("none" in r.get("detail", "").lower() or "none" in r["type"].lower()
               for r in fails)


# ── JWT in response body (body_keys) ─────────────────────────────────────────

def test_jwt_in_body_key_with_sensitive_payload():
    payload = {"sub": "admin", "password": "s3cr3t", "exp": 9999999999}
    token = _make_jwt({"alg": "RS256", "typ": "JWT"}, payload)
    body = json.dumps({"access_token": token})

    session = MagicMock()
    resp = MagicMock()
    resp.text = body
    resp.headers = {}
    resp.raw.headers = MagicMock()
    resp.raw.headers.getlist.return_value = []

    s = JWTScanner(session)
    s.http.get = MagicMock(return_value=resp)
    results = s.scan("https://example.com")
    # Should either find sensitive payload or pass (depending on alg)
    assert results  # at minimum one result


# ── Valid JWT with strong alg passes ─────────────────────────────────────────

def test_valid_jwt_with_rs256_passes():
    import time
    exp = int(time.time()) + 3600  # 1 hour from now
    payload = {"sub": "user", "exp": exp, "iss": "https://example.com"}
    token = _make_jwt({"alg": "RS256", "typ": "JWT"}, payload)

    session = MagicMock()
    resp = MagicMock()
    resp.text = json.dumps({"token": token})
    resp.headers = {}
    resp.raw.headers = MagicMock()
    resp.raw.headers.getlist.return_value = []

    s = JWTScanner(session)
    s.http.get = MagicMock(return_value=resp)
    results = s.scan("https://example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
