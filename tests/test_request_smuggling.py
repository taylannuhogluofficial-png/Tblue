"""Tests for tblue.scanner.request_smuggling — RequestSmugglingScanner."""

import pytest
from unittest.mock import MagicMock, patch

from tblue.scanner.request_smuggling import RequestSmugglingScanner

URL = "https://example.com"


def _make_scanner():
    session = MagicMock()
    return RequestSmugglingScanner(session)


def _mock_resp(status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = ""
    r.headers = headers or {}
    return r


# ── None response ─────────────────────────────────────────────────────────────

def test_scan_none_response():
    scanner = _make_scanner()
    with patch.object(scanner.http, "get", return_value=None):
        results = scanner.scan(URL)
    assert results == []


# ── Clean response → PASS ─────────────────────────────────────────────────────

def test_scan_clean_no_indicators():
    scanner = _make_scanner()
    # First call: baseline; all subsequent calls: TE probe returns 400 (rejected — good)
    baseline = _mock_resp(headers={"server": "nginx/1.24.0"})
    probe_rejected = _mock_resp(status=400)
    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return baseline
        return probe_rejected

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


# ── Dual CL + TE ──────────────────────────────────────────────────────────────

def test_scan_dual_cl_te():
    scanner = _make_scanner()
    resp = _mock_resp(headers={
        "content-length": "100",
        "transfer-encoding": "chunked",
    })
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("dual CL+TE" in w["type"] for w in warns)


def test_scan_only_cl_no_te():
    scanner = _make_scanner()
    resp = _mock_resp(headers={"content-length": "100"})
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    assert not any("dual CL+TE" in r["type"] for r in results)


def test_scan_te_without_chunked():
    scanner = _make_scanner()
    resp = _mock_resp(headers={
        "content-length": "100",
        "transfer-encoding": "identity",
    })
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    assert not any("dual CL+TE" in r["type"] for r in results)


# ── Suspicious TE value ───────────────────────────────────────────────────────

def test_scan_suspicious_te_xchunked():
    scanner = _make_scanner()
    resp = _mock_resp(headers={"transfer-encoding": "xchunked"})
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("suspicious Transfer-Encoding" in w["type"] for w in warns)


def test_scan_suspicious_te_chunked_ext():
    scanner = _make_scanner()
    resp = _mock_resp(headers={"transfer-encoding": "chunked;ext=foo"})
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("suspicious" in w["type"] for w in warns)


# ── Proxy chain ────────────────────────────────────────────────────────────────

def test_scan_single_proxy_header_no_warn():
    scanner = _make_scanner()
    resp = _mock_resp(headers={"via": "1.1 proxy.example.com"})
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    # Single proxy header not enough to trigger warning
    assert not any("proxy chain" in r["type"] for r in results)


def test_scan_multi_proxy_headers():
    scanner = _make_scanner()
    resp = _mock_resp(headers={
        "via": "1.1 frontend",
        "x-forwarded-for": "10.0.0.1",
        "x-cache": "MISS",
    })
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("proxy chain" in w["type"] for w in warns)


def test_scan_cloudflare_and_forwarded():
    scanner = _make_scanner()
    resp = _mock_resp(headers={
        "cf-ray": "1234abc",
        "x-forwarded-for": "1.2.3.4",
        "x-real-ip": "1.2.3.4",
    })
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("proxy" in w["type"] for w in warns)


# ── Known-vulnerable server ───────────────────────────────────────────────────

def test_scan_vulnerable_nginx_version():
    scanner = _make_scanner()
    resp = _mock_resp(headers={"server": "nginx/1.10.3"})
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("vulnerable server" in f["type"] for f in fails)


def test_scan_vulnerable_apache_version():
    scanner = _make_scanner()
    resp = _mock_resp(headers={"server": "Apache/2.4.10"})
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("vulnerable server" in f["type"] for f in fails)


def test_scan_safe_nginx_version():
    scanner = _make_scanner()
    resp = _mock_resp(headers={"server": "nginx/1.24.0"})
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    assert not any("vulnerable server" in r["type"] for r in results)


def test_scan_x_powered_by_iis():
    scanner = _make_scanner()
    resp = _mock_resp(headers={"x-powered-by": "Microsoft-IIS/8.5"})
    with patch.object(scanner.http, "get", return_value=resp):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("vulnerable server" in f["type"] for f in fails)


# ── Ambiguous TE probe ────────────────────────────────────────────────────────

def test_scan_te_probe_accepted():
    scanner = _make_scanner()
    # First call: baseline (no issues)
    # Second+ calls: TE probe returns 200 (server accepts ambiguous TE)
    baseline = _mock_resp(headers={})
    probe_accepted = _mock_resp(status=200)

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return baseline
        return probe_accepted

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("ambiguous Transfer-Encoding" in w["type"] for w in warns)


def test_scan_te_probe_rejected():
    scanner = _make_scanner()
    baseline = _mock_resp(headers={})
    probe_rejected = _mock_resp(status=400)

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return baseline
        return probe_rejected

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    # 400 rejection is good — no warning for this
    assert not any("ambiguous Transfer-Encoding" in r["type"] for r in results)


def test_scan_te_probe_exception():
    scanner = _make_scanner()
    baseline = _mock_resp(headers={})

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return baseline
        raise ConnectionError("network error")

    with patch.object(scanner.http, "get", side_effect=side_effect):
        # Should not crash
        results = scanner.scan(URL)


def test_scan_te_probe_none():
    scanner = _make_scanner()
    baseline = _mock_resp(headers={})

    call_count = {"n": 0}

    def side_effect(url, headers=None, **kwargs):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return baseline
        return None

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    # None probe → no false positive
    assert not any("ambiguous Transfer-Encoding" in r["type"] for r in results)
