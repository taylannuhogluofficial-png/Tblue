"""Tests for tblue.scanner.cache_poisoning — CachePoisoningScanner."""

import pytest
from unittest.mock import MagicMock, patch

from tblue.scanner.cache_poisoning import CachePoisoningScanner

URL = "https://example.com"


def _make_scanner():
    session = MagicMock()
    return CachePoisoningScanner(session)


def _mock_resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


# ── baseline None → early return ─────────────────────────────────────────────

def test_scan_none_baseline():
    scanner = _make_scanner()
    with patch.object(scanner.http, "get", return_value=None):
        results = scanner.scan(URL)
    assert results == []


# ── No reflection — PASS ─────────────────────────────────────────────────────

def test_scan_no_reflection():
    scanner = _make_scanner()
    resp = _mock_resp(body="<html>normal page</html>", headers={"cache-control": "no-store"})
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


# ── Reflection not cacheable → WARN ──────────────────────────────────────────

def test_scan_reflection_not_cacheable():
    scanner = _make_scanner()
    # Baseline + probe responses — probe reflects canary but CC says no-store
    baseline = _mock_resp(body="normal", headers={"cache-control": "no-store"})
    # Probe reflects canary in body but also has no-store
    canary_body = "tblue-probe.invalid in response"
    probe = _mock_resp(body=canary_body, headers={
        "cache-control": "no-store",
        "vary": "",
    })

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return baseline
        return probe

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    # Should have reflection warning (not cacheable → WARN not FAIL)
    assert warns


# ── Reflection and cacheable → FAIL ──────────────────────────────────────────

def test_scan_reflection_and_cacheable():
    scanner = _make_scanner()
    baseline = _mock_resp(body="normal", headers={"cache-control": "public, max-age=3600"})
    # Probe: reflects canary, cacheable, no Vary
    canary_body = "tblue-probe.invalid is the host"
    probe = _mock_resp(body=canary_body, headers={
        "cache-control": "public, max-age=3600",
        "vary": "",
    })

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return baseline
        return probe

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert "cacheable" in fails[0]["type"]


# ── Reflection in Location header ────────────────────────────────────────────

def test_scan_reflection_in_location_header():
    scanner = _make_scanner()
    baseline = _mock_resp(body="normal", headers={})
    probe = _mock_resp(body="", headers={
        "location": "https://tblue-probe.invalid/redirect",
        "cache-control": "",
        "vary": "",
    })

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return baseline
        return probe

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    assert any(r["status"] in ("WARN", "FAIL") for r in results)


# ── Header in Vary → not flagged as cacheable ────────────────────────────────

def test_scan_vary_includes_all_tested_headers():
    scanner = _make_scanner()
    baseline = _mock_resp(body="normal", headers={"cache-control": "public, max-age=600"})
    # Canary is reflected but ALL tested headers appear in Vary → all properly keyed
    canary_body = "tblue-probe.invalid tblue-probe reflected"
    # Include every header name we probe so none is treated as unkeyed
    probe = _mock_resp(body=canary_body, headers={
        "cache-control": "public, max-age=600",
        "vary": "x-forwarded-host, x-host, x-forwarded-server, x-forwarded-proto, x-original-url",
    })

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return baseline
        return probe

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    # All headers are in Vary → reflected_only (WARN), not FAIL (cacheable)
    fails = [r for r in results if r["status"] == "FAIL" and "cacheable" in r["type"]]
    assert not fails


# ── Probe returns None ────────────────────────────────────────────────────────

def test_scan_probe_returns_none():
    scanner = _make_scanner()
    baseline = _mock_resp(body="normal", headers={})
    # Second call (probe) returns None — should be skipped
    responses = [baseline, None, None, None, None, None]
    with patch.object(scanner.http, "get", side_effect=responses):
        results = scanner.scan(URL)
    # No false positives
    assert not any(r["status"] == "FAIL" and "cacheable" in r["type"] for r in results)


# ── Probe exception ───────────────────────────────────────────────────────────

def test_scan_probe_exception():
    scanner = _make_scanner()
    baseline = _mock_resp(body="normal", headers={})

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return baseline
        raise ConnectionError("network error")

    with patch.object(scanner.http, "get", side_effect=side_effect):
        # Should not crash
        results = scanner.scan(URL)


# ── Cache header analysis: max-age + no Vary ─────────────────────────────────

def test_scan_cacheable_no_vary_warn():
    scanner = _make_scanner()
    # Response has max-age > 0 but no Vary header
    resp = _mock_resp(body="page", headers={
        "cache-control": "public, max-age=7200",
        "vary": "",
    })
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("no Vary" in w["type"] for w in warns)


def test_scan_s_maxage_no_vary_warn():
    scanner = _make_scanner()
    resp = _mock_resp(body="page", headers={
        "cache-control": "s-maxage=3600",
        "vary": "",
    })
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("no Vary" in w["type"] for w in warns)


def test_scan_no_store_suppresses_vary_warn():
    scanner = _make_scanner()
    resp = _mock_resp(body="page", headers={
        "cache-control": "no-store, max-age=600",
        "vary": "",
    })
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    # no-store takes precedence — no Vary warning
    assert not any("no Vary" in r["type"] for r in results)


def test_scan_private_suppresses_vary_warn():
    scanner = _make_scanner()
    resp = _mock_resp(body="page", headers={
        "cache-control": "private, max-age=600",
        "vary": "",
    })
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    assert not any("no Vary" in r["type"] for r in results)


def test_scan_age_header_present():
    """Response with Age header should not crash (covers lines 154-159)."""
    scanner = _make_scanner()
    resp = _mock_resp(body="page", headers={
        "cache-control": "public, max-age=3600",
        "vary": "accept-encoding",
        "age": "60",
    })
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    # Age header handled without crash; no-vary warning may fire since vary is present but max-age > 0
    assert results is not None


def test_scan_age_header_with_no_store():
    """Positive Age with no-store CC → age_sec > 0 but no-store True → False branch at line 156."""
    scanner = _make_scanner()
    resp = _mock_resp(body="page", headers={
        "cache-control": "no-store",
        "age": "120",
    })
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    assert results is not None


def test_scan_age_header_invalid():
    """Non-integer Age header should not crash (covers ValueError in lines 154-159)."""
    scanner = _make_scanner()
    resp = _mock_resp(body="page", headers={
        "cache-control": "public",
        "age": "not-a-number",
    })
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    assert results is not None


def test_scan_max_age_zero_no_vary_warn():
    scanner = _make_scanner()
    resp = _mock_resp(body="page", headers={
        "cache-control": "max-age=0",
        "vary": "",
    })
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    # max-age=0 means not actually cached — no warn
    assert not any("no Vary" in r["type"] for r in results)
