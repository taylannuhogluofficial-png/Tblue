"""Tests for tblue.scanner.http_parameter_pollution — HPP scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.http_parameter_pollution import HTTPParameterPollutionScanner


def _scanner():
    session = MagicMock()
    return HTTPParameterPollutionScanner(session)


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
        results = s.scan("https://example.com/?q=test")
    assert any(r["status"] == "PASS" for r in results)


# ── Second duplicate value echoed → WARN ─────────────────────────────────────

def test_last_value_echoed_warns():
    s = _scanner()
    clean = _resp(200, "")
    # Response body echoes the sentinel_b but not sentinel_a
    polluted = _resp(200, "Result: hpp_test_second shown here")

    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean  # Initial scan
        return polluted   # All probe calls return echoed second value

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?id=123")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("last duplicate" in r["type"].lower() for r in warns)


# ── Both values echoed → WARN ─────────────────────────────────────────────────

def test_both_values_echoed_warns():
    s = _scanner()
    clean = _resp(200, "")
    both = _resp(200, "hpp_test_first and hpp_test_second both here")

    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        return clean if call_count[0] == 1 else both

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?name=test")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("both" in r["type"].lower() for r in warns)


# ── Array notation accepted → WARN ───────────────────────────────────────────

def test_array_notation_warns():
    s = _scanner()
    clean = _resp(200, "")
    # Returns sentinel when array notation is used
    array_resp = _resp(200, "hpp_test_first in array context")

    def get_side_effect(url, **kwargs):
        if "[]=" in url or "[0]=" in url:
            return array_resp
        return clean

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?id=1")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("array" in r["type"].lower() for r in warns)


# ── Encoded %26 duplication → WARN ───────────────────────────────────────────

def test_encoded_duplication_warns():
    s = _scanner()
    clean = _resp(200, "")
    encoded_resp = _resp(200, "hpp_test_second via encoded amp")

    def get_side_effect(url, **kwargs):
        if "%26" in url:
            return encoded_resp
        return clean

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?q=foo")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("encoded" in r["type"].lower() or "%26" in r["type"].lower() for r in warns)


# ── No HPP → PASS ─────────────────────────────────────────────────────────────

def test_no_hpp_passes():
    s = _scanner()
    clean = _resp(200, "nothing interesting here")
    with patch.object(s.http, "get", return_value=clean):
        results = s.scan("https://example.com/?id=42")
    assert any(r["status"] == "PASS" for r in results)


# ── Probe None response (mid-scan) → no crash ────────────────────────────────

def test_probe_returns_none_no_crash():
    s = _scanner()
    clean = _resp(200, "")

    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean
        return None  # All probes fail

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?page=1")
    # Should not raise — should return PASS since no injection was confirmed
    assert isinstance(results, list)
