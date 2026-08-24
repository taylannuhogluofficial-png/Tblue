"""Tests for Server-Timing Information Disclosure scanner."""

import pytest
from unittest.mock import MagicMock, patch

from tblue.scanner.server_timing import ServerTimingScanner


def _make_scanner():
    session = MagicMock()
    return ServerTimingScanner(session)


def _resp(text="", status_code=200, headers=None):
    r = MagicMock()
    r.text = text
    r.status_code = status_code
    r.headers = headers or {}
    return r


# 1 — Unreachable target
def test_unreachable_target():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert len(results) == 1
    assert results[0]["status"] == "PASS"
    assert "unreachable" in results[0]["type"].lower()


# 2 — No Server-Timing header present → PASS
def test_no_server_timing_header():
    s = _make_scanner()
    main_resp = _resp("<html></html>", headers={"content-type": "text/html"})

    def fake_get(url, **kw):
        return main_resp if url == "https://example.com" else _resp(status_code=404, headers={})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] in ("FAIL", "WARN") for r in results)


# 3 — Internal IP in Server-Timing → FAIL
def test_internal_ip_in_server_timing_fail():
    s = _make_scanner()
    main_resp = _resp(
        "<html></html>",
        headers={"server-timing": "cache;dur=23, origin=192.168.1.100;dur=12"}
    )

    with patch.object(s.http, "get", side_effect=lambda url, **kw: main_resp if url == "https://example.com" else _resp(status_code=404, headers={})):
        results = s.scan("https://example.com")

    ip_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(ip_findings) >= 1
    assert "IP" in ip_findings[0]["detail"] or "ip" in ip_findings[0]["detail"].lower()


# 4 — Auth metric name in Server-Timing → FAIL (timing side-channel)
def test_auth_metric_in_server_timing_fail():
    s = _make_scanner()
    main_resp = _resp(
        "<html></html>",
        headers={"server-timing": "auth;dur=45.2, total;dur=150"}
    )

    with patch.object(s.http, "get", side_effect=lambda url, **kw: main_resp if url == "https://example.com" else _resp(status_code=404, headers={})):
        results = s.scan("https://example.com")

    auth_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(auth_findings) >= 1
    assert "timing" in auth_findings[0]["detail"].lower()


# 5 — Database service name in Server-Timing → WARN
def test_db_service_name_in_server_timing_warn():
    s = _make_scanner()
    main_resp = _resp(
        "<html></html>",
        headers={"server-timing": "db;dur=53.1, cache;dur=5.2, total;dur=200"}
    )

    with patch.object(s.http, "get", side_effect=lambda url, **kw: main_resp if url == "https://example.com" else _resp(status_code=404, headers={})):
        results = s.scan("https://example.com")

    findings = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert len(findings) >= 1
    assert any("service" in r["detail"].lower() or "db" in r["detail"].lower() for r in findings)


# 6 — Datacenter region in Server-Timing → WARN
def test_datacenter_region_in_server_timing_warn():
    s = _make_scanner()
    main_resp = _resp(
        "<html></html>",
        headers={"server-timing": "total;dur=120, dc=us-east-1;dur=0"}
    )

    with patch.object(s.http, "get", side_effect=lambda url, **kw: main_resp if url == "https://example.com" else _resp(status_code=404, headers={})):
        results = s.scan("https://example.com")

    findings = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert len(findings) >= 1


# 7 — Internal hostname in Server-Timing → FAIL
def test_internal_hostname_in_server_timing_fail():
    s = _make_scanner()
    main_resp = _resp(
        "<html></html>",
        headers={"server-timing": "backend=app01.internal;dur=87, cache;dur=12"}
    )

    with patch.object(s.http, "get", side_effect=lambda url, **kw: main_resp if url == "https://example.com" else _resp(status_code=404, headers={})):
        results = s.scan("https://example.com")

    findings = [r for r in results if r["status"] == "FAIL"]
    assert len(findings) >= 1
    assert "hostname" in findings[0]["detail"].lower() or "internal" in findings[0]["detail"].lower()


# 8 — Generic metric names only → WARN (header present, review manually)
def test_generic_metric_names_warn():
    s = _make_scanner()
    main_resp = _resp(
        "<html></html>",
        headers={"server-timing": "total;dur=120, render;dur=45, css;dur=10"}
    )

    with patch.object(s.http, "get", side_effect=lambda url, **kw: main_resp if url == "https://example.com" else _resp(status_code=404, headers={})):
        results = s.scan("https://example.com")

    # Header present but no sensitive data → WARN
    warn_findings = [r for r in results if r["status"] == "WARN"]
    assert len(warn_findings) >= 1
    assert "review" in warn_findings[0]["detail"].lower()


# 9 — SQL metric in Server-Timing → WARN
def test_sql_metric_in_server_timing_warn():
    s = _make_scanner()
    main_resp = _resp(
        "<html></html>",
        headers={"server-timing": "query;dur=120, render;dur=45"}
    )

    with patch.object(s.http, "get", side_effect=lambda url, **kw: main_resp if url == "https://example.com" else _resp(status_code=404, headers={})):
        results = s.scan("https://example.com")

    findings = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert len(findings) >= 1


# 10 — Server-Timing found on probed health endpoint
def test_server_timing_on_health_endpoint():
    s = _make_scanner()
    main_resp = _resp("<html></html>", headers={})
    health_resp = _resp(
        "",
        status_code=200,
        headers={"server-timing": "redis;dur=4, db;dur=55"}
    )

    def fake_get(url, **kw):
        if url == "https://example.com":
            return main_resp
        if "/health" in url:
            return health_resp
        return _resp(status_code=404, headers={})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    findings = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert len(findings) >= 1


# 11 — 404 on probed health endpoint is skipped
def test_404_probe_skipped():
    s = _make_scanner()
    main_resp = _resp("<html></html>", headers={})

    def fake_get(url, **kw):
        if url == "https://example.com":
            return main_resp
        return _resp(status_code=404, headers={"server-timing": "db;dur=12"})

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    # 404 responses are skipped — should be PASS overall
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] in ("FAIL", "WARN") for r in results)


# 12 — Exception during probe is handled gracefully
def test_exception_in_probe_handled():
    s = _make_scanner()
    main_resp = _resp("<html></html>", headers={})
    call_count = [0]

    def fake_get(url, **kw):
        if url == "https://example.com":
            return main_resp
        call_count[0] += 1
        raise ConnectionError("network error")

    with patch.object(s.http, "get", side_effect=fake_get):
        results = s.scan("https://example.com")

    assert call_count[0] > 0
    assert any(r["status"] == "PASS" for r in results)


# 13 — Loopback IP (127.x.x.x) in Server-Timing → FAIL
def test_loopback_ip_in_server_timing_fail():
    s = _make_scanner()
    main_resp = _resp(
        "<html></html>",
        headers={"server-timing": "origin=127.0.0.1;dur=10"}
    )

    with patch.object(s.http, "get", side_effect=lambda url, **kw: main_resp if url == "https://example.com" else _resp(status_code=404, headers={})):
        results = s.scan("https://example.com")

    fail_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_findings) >= 1


# 14 — Redis microservice name → WARN (service name)
def test_redis_microservice_name_warn():
    s = _make_scanner()
    main_resp = _resp(
        "<html></html>",
        headers={"server-timing": "redis;dur=3.5, total;dur=100"}
    )

    with patch.object(s.http, "get", side_effect=lambda url, **kw: main_resp if url == "https://example.com" else _resp(status_code=404, headers={})):
        results = s.scan("https://example.com")

    findings = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert len(findings) >= 1


# 15 — Server-Timing with svc.cluster.local hostname → FAIL
def test_k8s_cluster_hostname_fail():
    s = _make_scanner()
    main_resp = _resp(
        "<html></html>",
        headers={"server-timing": "upstream=api.default.svc.cluster.local;dur=22"}
    )

    with patch.object(s.http, "get", side_effect=lambda url, **kw: main_resp if url == "https://example.com" else _resp(status_code=404, headers={})):
        results = s.scan("https://example.com")

    fail_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_findings) >= 1


# 16 — JWT timing metric → FAIL (auth timing side-channel)
def test_jwt_timing_metric_fail():
    s = _make_scanner()
    main_resp = _resp(
        "<html></html>",
        headers={"server-timing": "jwt;dur=12, total;dur=89"}
    )

    with patch.object(s.http, "get", side_effect=lambda url, **kw: main_resp if url == "https://example.com" else _resp(status_code=404, headers={})):
        results = s.scan("https://example.com")

    fail_findings = [r for r in results if r["status"] == "FAIL"]
    assert len(fail_findings) >= 1
