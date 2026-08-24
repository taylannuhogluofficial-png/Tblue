"""Tests for advanced cookie security checks (__Secure-/__Host- prefix, SameSite=None)."""

from unittest.mock import MagicMock
from tblue.scanner.cookie_advanced import CookieAdvancedScanner


def _scanner(set_cookie_headers: list = None):
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {}
        if set_cookie_headers:
            resp.headers["Set-Cookie"] = set_cookie_headers[0]
        # Simulate resp.raw.headers for multi-cookie extraction
        raw_headers = []
        for v in (set_cookie_headers or []):
            raw_headers.append(("set-cookie", v))
        resp.raw = MagicMock()
        resp.raw.headers = raw_headers
        return resp

    session.request.side_effect = fake_request
    return CookieAdvancedScanner(session)


# ── No cookies ────────────────────────────────────────────────────────────────

def test_no_cookies_passes():
    scanner = _scanner([])
    results = scanner.scan("https://example.com")
    assert any("no cookies" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ── __Secure- prefix ──────────────────────────────────────────────────────────

def test_secure_prefix_with_secure_flag_clean():
    scanner = _scanner(["__Secure-session=abc; Secure; HttpOnly; SameSite=Strict"])
    results = scanner.scan("https://example.com")
    assert not any("__secure- prefix violation" in r["type"].lower() for r in results)


def test_secure_prefix_without_secure_flag_fails():
    scanner = _scanner(["__Secure-session=abc; HttpOnly; SameSite=Strict"])
    results = scanner.scan("https://example.com")
    assert any("__secure- prefix violation" in r["type"].lower() and r["status"] == "FAIL"
               for r in results)


# ── __Host- prefix ────────────────────────────────────────────────────────────

def test_host_prefix_fully_correct_clean():
    scanner = _scanner(["__Host-session=abc; Secure; HttpOnly; Path=/; SameSite=Strict"])
    results = scanner.scan("https://example.com")
    assert not any("__host- prefix violation" in r["type"].lower() for r in results)


def test_host_prefix_missing_secure_fails():
    scanner = _scanner(["__Host-session=abc; HttpOnly; Path=/"])
    results = scanner.scan("https://example.com")
    assert any("__host- prefix violation" in r["type"].lower() and r["status"] == "FAIL"
               for r in results)


def test_host_prefix_with_domain_fails():
    scanner = _scanner(["__Host-session=abc; Secure; HttpOnly; Path=/; Domain=example.com"])
    results = scanner.scan("https://example.com")
    assert any("__host- prefix violation" in r["type"].lower() and r["status"] == "FAIL"
               for r in results)


def test_host_prefix_wrong_path_fails():
    scanner = _scanner(["__Host-session=abc; Secure; HttpOnly; Path=/app"])
    results = scanner.scan("https://example.com")
    assert any("__host- prefix violation" in r["type"].lower() and r["status"] == "FAIL"
               for r in results)


# ── SameSite=None ─────────────────────────────────────────────────────────────

def test_samesite_none_with_secure_clean():
    scanner = _scanner(["embed_token=abc; SameSite=None; Secure; HttpOnly"])
    results = scanner.scan("https://example.com")
    assert not any("samesite=none without secure" in r["type"].lower() for r in results)


def test_samesite_none_without_secure_fails():
    scanner = _scanner(["embed_token=abc; SameSite=None; HttpOnly"])
    results = scanner.scan("https://example.com")
    assert any("samesite=none without secure" in r["type"].lower() and r["status"] == "FAIL"
               for r in results)


# ── Sensitive name without HttpOnly ───────────────────────────────────────────

def test_session_cookie_without_httponly_warns():
    scanner = _scanner(["session=abc; Secure; SameSite=Strict"])
    results = scanner.scan("https://example.com")
    assert any("missing httponly" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_session_cookie_with_httponly_clean():
    scanner = _scanner(["session=abc; Secure; HttpOnly; SameSite=Strict"])
    results = scanner.scan("https://example.com")
    assert not any("missing httponly" in r["type"].lower() for r in results)


def test_auth_token_without_httponly_warns():
    scanner = _scanner(["auth_token=xyz; Secure; SameSite=Lax"])
    results = scanner.scan("https://example.com")
    assert any("missing httponly" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Overly broad Domain ───────────────────────────────────────────────────────

def test_overly_broad_domain_warns():
    scanner = _scanner(["session=abc; Secure; HttpOnly; Domain=.example.com; Path=/"])
    results = scanner.scan("https://api.example.com")
    assert any("overly broad domain" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


def test_exact_domain_clean():
    scanner = _scanner(["session=abc; Secure; HttpOnly; Domain=example.com; Path=/"])
    results = scanner.scan("https://example.com")
    # Same host — should not flag
    assert not any("overly broad" in r["type"].lower() for r in results)
