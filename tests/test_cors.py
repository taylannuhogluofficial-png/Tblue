"""
Tests for CORS misconfiguration scanner.
"""

import pytest
from unittest.mock import MagicMock
from tblue.scanner.cors import CORSScanner

_EVIL = "https://evil-tblue-probe.com"


def make_scanner(origin_map: dict = None) -> CORSScanner:
    """
    origin_map: {origin_sent: (acao_returned, acac_returned)}
    Any origin not in map returns no CORS headers.
    """
    origin_map = origin_map or {}
    session    = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.url = url
        sent_origin = (kwargs.get("headers") or {}).get("Origin", "")
        acao, acac = origin_map.get(sent_origin, ("", ""))
        resp.headers = {
            "access-control-allow-origin":      acao,
            "access-control-allow-credentials": acac,
        }
        return resp

    session.request.side_effect = fake_request
    return CORSScanner(session)


# ── Reflected origin ──────────────────────────────────────────────────────────

def test_reflected_origin_with_credentials_fails():
    scanner = make_scanner({_EVIL: (_EVIL, "true")})
    results = scanner.scan("https://example.com")
    assert any("reflected origin with credentials" in r["type"].lower() and r["status"] == "FAIL"
               for r in results)


def test_reflected_origin_without_credentials_warns():
    scanner = make_scanner({_EVIL: (_EVIL, "")})
    results = scanner.scan("https://example.com")
    assert any("origin reflected without credentials" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


# ── Null origin ───────────────────────────────────────────────────────────────

def test_null_origin_with_credentials_fails():
    scanner = make_scanner({"null": ("null", "true")})
    results = scanner.scan("https://example.com")
    assert any("null origin with credentials" in r["type"].lower() and r["status"] == "FAIL"
               for r in results)


def test_null_origin_without_credentials_warns():
    scanner = make_scanner({"null": ("null", "")})
    results = scanner.scan("https://example.com")
    assert any("null origin accepted" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


# ── Wildcard ─────────────────────────────────────────────────────────────────

def test_wildcard_acao_warns():
    scanner = make_scanner({"https://tblue-check.com": ("*", "")})
    results = scanner.scan("https://example.com")
    assert any("wildcard" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_wildcard_with_credentials_warns():
    scanner = make_scanner({"https://tblue-check.com": ("*", "true")})
    results = scanner.scan("https://example.com")
    assert any("wildcard acao with credentials" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


# ── Clean policy ──────────────────────────────────────────────────────────────

def test_clean_policy_passes():
    scanner = make_scanner()  # no CORS headers returned for any origin
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] == "FAIL" for r in results)


def test_same_origin_policy_passes():
    scanner = make_scanner({"https://example.com": ("https://example.com", "true")})
    results = scanner.scan("https://example.com")
    # Reflecting your own origin is fine — not caught as evil origin
    assert any(r["status"] == "PASS" for r in results)


# ── Subdomain wildcard ────────────────────────────────────────────────────────

def test_subdomain_wildcard_reflection_warns():
    sub_evil = "https://evil.example.com"
    scanner  = make_scanner({sub_evil: (sub_evil, "")})
    results  = scanner.scan("https://example.com")
    assert any("subdomain-wildcard" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


# ── Error handling ────────────────────────────────────────────────────────────

def test_failed_request_returns_pass():
    session = MagicMock()
    session.request.side_effect = Exception("Timeout")
    scanner = CORSScanner(session, retries=1)
    results = scanner.scan("https://example.com")
    # No issues detected when request fails — PASS emitted
    assert any(r["status"] == "PASS" for r in results)


# ── None response paths ───────────────────────────────────────────────────────

def test_none_response_from_probe_reflected_returns_pass():
    # When the probe for reflected origin returns None (all retries failed),
    # no reflection is detected and the overall CORS result should not be FAIL.
    session = MagicMock()
    session.request.return_value = None
    scanner = CORSScanner(session)
    results = scanner.scan("https://example.com")
    assert not any(r["status"] == "FAIL" for r in results)


def test_null_probe_none_response_does_not_crash():
    # First probe (reflected) returns a clean response, null probe returns None.
    call_count = [0]

    def fake_request(method, url, **kwargs):
        call_count[0] += 1
        origin = (kwargs.get("headers") or {}).get("Origin", "")
        if origin == "null":
            return None
        resp = MagicMock()
        resp.status_code = 200
        resp.url = url
        resp.headers = {"access-control-allow-origin": "", "access-control-allow-credentials": ""}
        return resp

    session = MagicMock()
    session.request.side_effect = fake_request
    scanner = CORSScanner(session)
    results = scanner.scan("https://example.com")
    assert isinstance(results, list)


# ── Subdomain reflection with credentials ────────────────────────────────────

def test_subdomain_reflection_with_credentials_warns():
    sub_evil = "https://evil.example.com"

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.url = url
        origin = (kwargs.get("headers") or {}).get("Origin", "")
        if origin == sub_evil:
            resp.headers = {
                "access-control-allow-origin":      sub_evil,
                "access-control-allow-credentials": "true",
            }
        else:
            resp.headers = {"access-control-allow-origin": "", "access-control-allow-credentials": ""}
        return resp

    session = MagicMock()
    session.request.side_effect = fake_request
    scanner = CORSScanner(session)
    results = scanner.scan("https://example.com")
    # Scanner checks subdomain reflection when evil origin is not directly reflected
    assert any(r["status"] in ("WARN", "FAIL") for r in results)
