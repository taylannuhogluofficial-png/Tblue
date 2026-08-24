"""Tests for Cross-Site Leak (XSLeak) Detection scanner."""

import pytest
from unittest.mock import MagicMock, patch

from tblue.scanner.xsleak import XSLeakScanner


def _make_scanner():
    session = MagicMock()
    return XSLeakScanner(session)


def _resp(text="", status_code=200, headers=None):
    r = MagicMock()
    r.text = text
    r.status_code = status_code
    r.headers = headers or {}
    return r


def _secure_headers():
    return {
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Resource-Policy": "same-origin",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
    }


# 1 — Unreachable target → PASS
def test_unreachable_target():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert len(results) == 1
    assert results[0]["status"] == "PASS"


# 2 — All security headers present → PASS
def test_all_headers_present_pass():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>", headers=_secure_headers())

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    assert all(r["status"] == "PASS" for r in results)


# 3 — Missing COOP → WARN
def test_missing_coop_warn():
    s = _make_scanner()
    headers = {
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Resource-Policy": "same-origin",
        "X-Frame-Options": "DENY",
    }

    def fake_get(url, **kw):
        return _resp("<html></html>", headers=headers)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("coop" in r["type"].lower() or "opener" in r["type"].lower()
               for r in warn)


# 4 — Unsafe COOP value → WARN
def test_unsafe_coop_value_warn():
    s = _make_scanner()
    headers = {
        "Cross-Origin-Opener-Policy": "unsafe-none",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "X-Frame-Options": "DENY",
    }

    def fake_get(url, **kw):
        return _resp("<html></html>", headers=headers)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("coop" in r["type"].lower() or "unsafe" in r["type"].lower()
               for r in warn)


# 5 — Missing COEP → WARN
def test_missing_coep_warn():
    s = _make_scanner()
    headers = {
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "X-Frame-Options": "DENY",
    }

    def fake_get(url, **kw):
        return _resp("<html></html>", headers=headers)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("coep" in r["type"].lower() or "embedder" in r["type"].lower()
               for r in warn)


# 6 — Missing CORP → WARN
def test_missing_corp_warn():
    s = _make_scanner()
    headers = {
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "X-Frame-Options": "DENY",
    }

    def fake_get(url, **kw):
        return _resp("<html></html>", headers=headers)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("corp" in r["type"].lower() or "resource" in r["type"].lower()
               for r in warn)


# 7 — No framing protection → WARN
def test_no_framing_protection_warn():
    s = _make_scanner()
    headers = {
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Resource-Policy": "same-origin",
        # No X-Frame-Options, no CSP frame-ancestors
    }

    def fake_get(url, **kw):
        return _resp("<html></html>", headers=headers)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("framing" in r["type"].lower() or "frame" in r["type"].lower()
               for r in warn)


# 8 — frame-ancestors in CSP satisfies framing check
def test_frame_ancestors_in_csp_satisfies_framing():
    s = _make_scanner()
    headers = {
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
        # No X-Frame-Options — but CSP has frame-ancestors
    }

    def fake_get(url, **kw):
        return _resp("<html></html>", headers=headers)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    framing = [r for r in results
               if "framing" in r["type"].lower() or "frame" in r["type"].lower()]
    assert len(framing) == 0


# 9 — Timing-Allow-Origin: * → WARN
def test_timing_allow_origin_wildcard_warn():
    s = _make_scanner()
    headers = {
        **_secure_headers(),
        "Timing-Allow-Origin": "*",
    }

    def fake_get(url, **kw):
        return _resp("<html></html>", headers=headers)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("timing" in r["type"].lower() for r in warn)


# 10 — Authenticated page missing Vary: Cookie → WARN
def test_authenticated_page_missing_vary_cookie():
    s = _make_scanner()
    auth_html = "<html><body><a href='/logout'>Logout</a><div>Dashboard</div></body></html>"
    headers = {
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Resource-Policy": "same-origin",
        "X-Frame-Options": "DENY",
        # No Vary: Cookie, no Cache-Control: no-store
    }

    def fake_get(url, **kw):
        return _resp(auth_html, headers=headers)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert any("vary" in r["type"].lower() or "cookie" in r["type"].lower()
               for r in warn)


# 11 — Cache-Control: no-store satisfies Vary: Cookie check
def test_cache_control_no_store_satisfies_vary():
    s = _make_scanner()
    auth_html = "<html><body><a href='/logout'>Logout</a></body></html>"
    headers = {
        **_secure_headers(),
        "Cache-Control": "no-store, private",
    }

    def fake_get(url, **kw):
        return _resp(auth_html, headers=headers)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    vary_warn = [r for r in results
                 if "vary" in r["type"].lower() or "cookie" in r["type"].lower()]
    assert len(vary_warn) == 0


# 12 — Vary: Cookie header satisfies the check
def test_vary_cookie_header_satisfies_check():
    s = _make_scanner()
    auth_html = "<html><body><a href='/logout'>Sign out</a></body></html>"
    headers = {
        **_secure_headers(),
        "Vary": "Cookie, Accept-Encoding",
    }

    def fake_get(url, **kw):
        return _resp(auth_html, headers=headers)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    vary_warn = [r for r in results
                 if "vary" in r["type"].lower() or "cookie" in r["type"].lower()]
    assert len(vary_warn) == 0


# 13 — Non-authenticated page does not check Vary: Cookie
def test_non_auth_page_skips_vary_check():
    s = _make_scanner()
    headers = {
        **_secure_headers(),
        # No Cache-Control, no Vary: Cookie — but page has no auth indicators
    }

    def fake_get(url, **kw):
        return _resp("<html><body><p>Welcome to our site</p></body></html>",
                     headers=headers)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    vary_warn = [r for r in results
                 if "vary" in r["type"].lower() or "cookie" in r["type"].lower()]
    assert len(vary_warn) == 0


# 14 — No headers at all → multiple WARNs
def test_no_headers_multiple_warns():
    s = _make_scanner()

    def fake_get(url, **kw):
        return _resp("<html></html>", headers={})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    warn = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert len(warn) >= 3  # COOP + COEP + CORP at minimum


# 15 — COOP: same-origin-allow-popups is accepted as safe
def test_coop_same_origin_allow_popups_is_safe():
    s = _make_scanner()
    headers = {
        "Cross-Origin-Opener-Policy": "same-origin-allow-popups",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Resource-Policy": "same-origin",
        "X-Frame-Options": "SAMEORIGIN",
    }

    def fake_get(url, **kw):
        return _resp("<html></html>", headers=headers)

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    coop_warn = [r for r in results
                 if "coop" in r["type"].lower() or "opener" in r["type"].lower()]
    assert len(coop_warn) == 0
