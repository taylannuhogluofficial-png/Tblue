"""Tests for tblue.scanner.weak_crypto — weak cryptography detection scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.weak_crypto import WeakCryptoScanner


def _scanner():
    session = MagicMock()
    return WeakCryptoScanner(session)


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


# ── MD5 ETag → WARN ──────────────────────────────────────────────────────────

def test_md5_etag_warns():
    s = _scanner()
    with patch.object(s.http, "get",
                      return_value=_resp(200, "<html></html>",
                                         {"ETag": '"d41d8cd98f00b204e9800998ecf8427e"'})):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("etag" in r["type"].lower() or "md5" in r["type"].lower() for r in warns)


# ── Content-MD5 header → WARN ─────────────────────────────────────────────────

def test_content_md5_header_warns():
    s = _scanner()
    with patch.object(s.http, "get",
                      return_value=_resp(200, "<html></html>",
                                         {"Content-MD5": "rL0Y20zC+Fzt72VPzMSk2A=="})):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("content-md5" in r["type"].lower() for r in warns)


# ── Low-entropy session token in Set-Cookie → FAIL ────────────────────────────

def test_low_entropy_session_fails():
    s = _scanner()
    with patch.object(s.http, "get",
                      return_value=_resp(200, "<html></html>",
                                         {"Set-Cookie": "session=abcdef01; Path=/; HttpOnly"})):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("entropy" in r["type"].lower() or "token" in r["type"].lower() for r in fails)


# ── MD5-length token in Set-Cookie → WARN ────────────────────────────────────

def test_md5_length_token_warns():
    s = _scanner()
    # 32 char hex — MD5 length
    md5_token = "a" * 32
    with patch.object(s.http, "get",
                      return_value=_resp(200, "<html></html>",
                                         {"Set-Cookie": f"authtoken={md5_token}; Path=/"})):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("md5" in r["type"].lower() or "token" in r["type"].lower() for r in warns)


# ── HTTP Digest with MD5 → FAIL ───────────────────────────────────────────────

def test_digest_md5_auth_fails():
    s = _scanner()
    with patch.object(s.http, "get",
                      return_value=_resp(401, "", {
                          "WWW-Authenticate": 'Digest realm="test", algorithm=MD5, nonce="abc"'
                      })):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("digest" in r["type"].lower() or "md5" in r["type"].lower() for r in fails)


# ── Weak cipher in body → WARN ───────────────────────────────────────────────

def test_weak_cipher_in_body_warns():
    s = _scanner()
    body = '<html><p>Server supports RC4 and DES ciphers for legacy clients</p></html>'
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("weak cipher" in r["type"].lower() or "rc4" in r["type"].lower() for r in warns)


# ── Weak cipher in Server header → WARN ──────────────────────────────────────

def test_weak_cipher_in_server_header_warns():
    s = _scanner()
    with patch.object(s.http, "get",
                      return_value=_resp(200, "<html></html>",
                                         {"Server": "Apache/2.4 (RC4-MD5 support)"})):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


# ── Clean response → PASS ─────────────────────────────────────────────────────

def test_clean_response_passes():
    s = _scanner()
    with patch.object(s.http, "get",
                      return_value=_resp(200, "<html></html>", {
                          "ETag": '"abc123-secure-opaque-token-xyz"',
                          "Set-Cookie": "sessionid=a" * 1 + "b" * 32 + "; Secure; HttpOnly",
                          "Cache-Control": "no-store",
                      })):
        results = s.scan("https://example.com")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
