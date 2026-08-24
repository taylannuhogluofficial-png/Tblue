"""Tests for tblue.scanner.ssrf_detection — SSRF detection scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.ssrf_detection import SSRFDetectionScanner


def _scanner():
    session = MagicMock()
    return SSRFDetectionScanner(session)


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
        results = s.scan("https://example.com/?url=https://good.com")
    assert any(r["status"] == "PASS" for r in results)


# ── No URL-type params → PASS ─────────────────────────────────────────────────

def test_no_url_params_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html></html>")):
        results = s.scan("https://example.com/?q=hello&page=2")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
    assert any("url-accepting" in r["type"].lower() for r in passes)


# ── Cloud metadata response → FAIL ────────────────────────────────────────────

def test_cloud_metadata_fails():
    s = _scanner()
    metadata_body = "ami-id\ninstance-id\nsecurity-credentials\niam/security-credentials"
    clean = _resp(200, "<html></html>")
    meta_resp = _resp(200, metadata_body)

    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean
        if "169.254" in url or "computeMetadata" in url:
            return meta_resp
        return clean

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?url=https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("metadata" in r["type"].lower() or "ssrf" in r["type"].lower() for r in fails)


# ── Private IP in response → WARN ─────────────────────────────────────────────

def test_private_ip_in_response_warns():
    s = _scanner()
    private_ip_body = "Connected to backend at 10.0.0.5. Version: 1.0"
    clean = _resp(200, "<html></html>")
    leak_resp = _resp(200, private_ip_body)

    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean
        return leak_resp

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?fetch=https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("private" in r["type"].lower() or "internal" in r["type"].lower() for r in warns)


# ── Connection refused error → WARN ───────────────────────────────────────────

def test_connection_refused_warns():
    s = _scanner()
    err_body = "Failed to fetch: connection refused to localhost:8080"
    clean = _resp(200, "<html></html>")
    err_resp = _resp(500, err_body)

    call_count = [0]
    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean
        return err_resp

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?src=image.png")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("connection" in r["type"].lower() or "ssrf" in r["type"].lower() for r in warns)


# ── GET returns None on probe → no crash ─────────────────────────────────────

def test_probe_none_no_crash():
    s = _scanner()
    clean = _resp(200, "<html></html>")
    call_count = [0]

    def get_side_effect(url, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return clean
        return None

    with patch.object(s.http, "get", side_effect=get_side_effect):
        results = s.scan("https://example.com/?url=https://example.com")
    assert isinstance(results, list)


# ── _collect_url_params from form input ──────────────────────────────────────

def test_collect_params_from_form():
    s = _scanner()
    body = '<html><form><input type="text" name="url"/></form></html>'
    params = s._collect_url_params("https://example.com/", body)
    assert "url" in params


# ── Clean response → PASS ─────────────────────────────────────────────────────

def test_clean_response_passes():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html>Image loaded OK</html>")):
        results = s.scan("https://example.com/?src=logo.png&callback=done")
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes
