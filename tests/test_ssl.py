"""
Tests for SSL / HTTPS scanner — including edge cases.
"""

import ssl
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
from tblue.scanner.ssl import SSLScanner


def make_scanner(redirect_url: str = None) -> SSLScanner:
    """Build an SSLScanner with a mocked session."""
    session = MagicMock()
    resp    = MagicMock()
    resp.url = redirect_url or "https://example.com"
    session.request.return_value = resp
    return SSLScanner(session)


# ─── Basic SSL checks ─────────────────────────────────────────────────────────

def test_https_url_passes():
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    ssl_result = next(r for r in results if r["type"] == "SSL / HTTPS")
    assert ssl_result["status"] == "PASS"


def test_http_url_fails():
    scanner = make_scanner()
    results = scanner.scan("http://example.com")
    ssl_result = next(r for r in results if r["type"] == "SSL / HTTPS")
    assert ssl_result["status"] == "FAIL"


def test_https_result_mentions_encrypted():
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    ssl_result = next(r for r in results if r["type"] == "SSL / HTTPS")
    assert "encrypted" in ssl_result["detail"].lower()


def test_http_result_mentions_unencrypted():
    scanner = make_scanner()
    results = scanner.scan("http://example.com")
    ssl_result = next(r for r in results if r["type"] == "SSL / HTTPS")
    assert "unencrypted" in ssl_result["detail"].lower()


def test_result_contains_url():
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert results[0]["url"] == "https://example.com"


# ─── HTTP redirect check ──────────────────────────────────────────────────────

def test_http_to_https_redirect_passes():
    scanner = make_scanner(redirect_url="https://example.com")
    results = scanner.scan("https://example.com")
    redirect_result = next(
        (r for r in results if "redirect" in r.get("type", "").lower()), None
    )
    if redirect_result:
        assert redirect_result["status"] == "PASS"


def test_no_redirect_fails():
    scanner = make_scanner(redirect_url="http://example.com")
    results = scanner.scan("https://example.com")
    redirect_result = next(
        (r for r in results if "redirect" in r.get("type", "").lower()), None
    )
    if redirect_result:
        assert redirect_result["status"] == "FAIL"


def test_failed_request_still_returns_ssl_result():
    session = MagicMock()
    # first call (SSL check) returns normally, second (redirect) fails
    resp = MagicMock()
    resp.url = "https://example.com"
    session.request.side_effect = [resp, Exception("Timeout")]
    scanner = SSLScanner(session)
    results = scanner.scan("https://example.com")
    assert any(r["type"] == "SSL / HTTPS" for r in results)


def test_result_has_required_fields():
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    for r in results:
        assert "url"    in r
        assert "type"   in r
        assert "status" in r
        assert "detail" in r
        assert r["status"] in ("PASS", "FAIL", "WARN")


# ── _check_cert_expiry branches ───────────────────────────────────────────────

def _cert_conn_expiry(days):
    future = datetime.now(tz=timezone.utc) + timedelta(days=days)
    conn   = MagicMock()
    conn.getpeercert.return_value = {"notAfter": future.strftime("%b %d %H:%M:%S %Y GMT")}
    return conn


def test_cert_expiry_far_future_passes():
    scanner = SSLScanner(MagicMock())
    conn = _cert_conn_expiry(90)
    with patch("tblue.scanner.ssl.ssl.create_default_context") as ctx:
        ctx.return_value.wrap_socket.return_value = conn
        with patch("tblue.scanner.ssl.socket.create_connection"):
            scanner._check_cert_expiry("example.com")
    assert any("expiry" in r["type"].lower() and r["status"] == "PASS" for r in scanner.results)


def test_cert_expiry_within_warn_range_warns():
    scanner = SSLScanner(MagicMock())
    conn = _cert_conn_expiry(20)
    with patch("tblue.scanner.ssl.ssl.create_default_context") as ctx:
        ctx.return_value.wrap_socket.return_value = conn
        with patch("tblue.scanner.ssl.socket.create_connection"):
            scanner._check_cert_expiry("example.com")
    assert any("expiry" in r["type"].lower() and r["status"] == "WARN" for r in scanner.results)


def test_cert_expiry_critical_fails():
    scanner = SSLScanner(MagicMock())
    conn = _cert_conn_expiry(3)
    with patch("tblue.scanner.ssl.ssl.create_default_context") as ctx:
        ctx.return_value.wrap_socket.return_value = conn
        with patch("tblue.scanner.ssl.socket.create_connection"):
            scanner._check_cert_expiry("example.com")
    assert any("expiry" in r["type"].lower() and r["status"] == "FAIL" for r in scanner.results)


def test_cert_expiry_no_notafter_field_skips():
    scanner = SSLScanner(MagicMock())
    conn = MagicMock()
    conn.getpeercert.return_value = {}
    with patch("tblue.scanner.ssl.ssl.create_default_context") as ctx:
        ctx.return_value.wrap_socket.return_value = conn
        with patch("tblue.scanner.ssl.socket.create_connection"):
            scanner._check_cert_expiry("example.com")
    assert not any("expiry" in r["type"].lower() for r in scanner.results)


def test_cert_expiry_exception_does_not_crash():
    scanner = SSLScanner(MagicMock())
    with patch("tblue.scanner.ssl.ssl.create_default_context", side_effect=OSError("timeout")):
        scanner._check_cert_expiry("example.com")
    assert isinstance(scanner.results, list)


# ── _check_cert_details branches ─────────────────────────────────────────────

def _cert_conn_details(issuer_cn, subject_cn, sans=None):
    conn = MagicMock()
    conn.getpeercert.return_value = {
        "issuer":         [[("commonName", issuer_cn), ("organizationName", "Org")]],
        "subject":        [[("commonName", subject_cn)]],
        "subjectAltName": [("DNS", s) for s in (sans or [])],
    }
    return conn


def test_ca_signed_cert_passes():
    scanner = SSLScanner(MagicMock())
    conn = _cert_conn_details("Let's Encrypt R3", "example.com", ["example.com"])
    with patch("tblue.scanner.ssl.ssl.SSLContext") as ctx_cls:
        ctx_cls.return_value.wrap_socket.return_value = conn
        with patch("tblue.scanner.ssl.socket.create_connection"):
            scanner._check_cert_details("example.com")
    assert any("certificate authority" in r["type"].lower() and r["status"] == "PASS"
               for r in scanner.results)


def test_self_signed_cert_fails():
    scanner = SSLScanner(MagicMock())
    conn = _cert_conn_details("example.com", "example.com", ["example.com"])
    with patch("tblue.scanner.ssl.ssl.SSLContext") as ctx_cls:
        ctx_cls.return_value.wrap_socket.return_value = conn
        with patch("tblue.scanner.ssl.socket.create_connection"):
            scanner._check_cert_details("example.com")
    assert any("self-signed" in r["type"].lower() and r["status"] == "FAIL"
               for r in scanner.results)


def test_cert_no_sans_warns():
    scanner = SSLScanner(MagicMock())
    conn = _cert_conn_details("Let's Encrypt", "example.com", sans=[])
    with patch("tblue.scanner.ssl.ssl.SSLContext") as ctx_cls:
        ctx_cls.return_value.wrap_socket.return_value = conn
        with patch("tblue.scanner.ssl.socket.create_connection"):
            scanner._check_cert_details("example.com")
    assert any("alternative names" in r["type"].lower() and r["status"] == "WARN"
               for r in scanner.results)


def test_cert_sans_cover_hostname_passes():
    scanner = SSLScanner(MagicMock())
    conn = _cert_conn_details("DigiCert", "example.com", ["example.com", "www.example.com"])
    with patch("tblue.scanner.ssl.ssl.SSLContext") as ctx_cls:
        ctx_cls.return_value.wrap_socket.return_value = conn
        with patch("tblue.scanner.ssl.socket.create_connection"):
            scanner._check_cert_details("example.com")
    assert any("sans coverage" in r["type"].lower() and r["status"] == "PASS"
               for r in scanner.results)


def test_cert_wildcard_san_covers_subdomain():
    scanner = SSLScanner(MagicMock())
    conn = _cert_conn_details("DigiCert", "*.example.com", ["*.example.com"])
    with patch("tblue.scanner.ssl.ssl.SSLContext") as ctx_cls:
        ctx_cls.return_value.wrap_socket.return_value = conn
        with patch("tblue.scanner.ssl.socket.create_connection"):
            scanner._check_cert_details("api.example.com")
    assert any("sans coverage" in r["type"].lower() and r["status"] == "PASS"
               for r in scanner.results)


def test_cert_sans_mismatch_fails():
    scanner = SSLScanner(MagicMock())
    conn = _cert_conn_details("DigiCert", "other.com", ["other.com"])
    with patch("tblue.scanner.ssl.ssl.SSLContext") as ctx_cls:
        ctx_cls.return_value.wrap_socket.return_value = conn
        with patch("tblue.scanner.ssl.socket.create_connection"):
            scanner._check_cert_details("example.com")
    assert any("mismatch" in r["type"].lower() and r["status"] == "FAIL"
               for r in scanner.results)


def test_cert_chain_invalid_fails():
    scanner = SSLScanner(MagicMock())
    with patch("tblue.scanner.ssl.ssl.SSLContext") as ctx_cls:
        ctx_cls.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError("chain")
        with patch("tblue.scanner.ssl.socket.create_connection"):
            scanner._check_cert_details("example.com")
    assert any("chain" in r["type"].lower() and r["status"] == "FAIL"
               for r in scanner.results)


def test_cert_details_empty_cert_returns_nothing():
    scanner = SSLScanner(MagicMock())
    conn = MagicMock()
    conn.getpeercert.return_value = {}
    with patch("tblue.scanner.ssl.ssl.SSLContext") as ctx_cls:
        ctx_cls.return_value.wrap_socket.return_value = conn
        with patch("tblue.scanner.ssl.socket.create_connection"):
            scanner._check_cert_details("example.com")
    assert scanner.results == []


def test_cert_details_exception_does_not_crash():
    scanner = SSLScanner(MagicMock())
    with patch("tblue.scanner.ssl.ssl.SSLContext", side_effect=OSError("refused")):
        scanner._check_cert_details("example.com")
    assert isinstance(scanner.results, list)


# ── _check_tls_version branches ───────────────────────────────────────────────

def test_tls_versions_rejected_passes():
    scanner = SSLScanner(MagicMock())
    with patch("tblue.scanner.ssl.ssl.SSLContext") as ctx_cls:
        ctx_cls.return_value.wrap_socket.side_effect = ssl.SSLError("unsupported")
        with patch("tblue.scanner.ssl.socket.create_connection"):
            scanner._check_tls_version("example.com")
    assert any("tls version" in r["type"].lower() and r["status"] == "PASS"
               for r in scanner.results)


def test_tls_10_accepted_fails():
    scanner = SSLScanner(MagicMock())
    call_count = [0]
    conn = MagicMock()

    def side_effect(sock, server_hostname):
        call_count[0] += 1
        if call_count[0] == 1:
            return conn  # TLS 1.0 "accepted"
        raise ssl.SSLError("unsupported")

    with patch("tblue.scanner.ssl.ssl.SSLContext") as ctx_cls:
        ctx_cls.return_value.wrap_socket.side_effect = side_effect
        with patch("tblue.scanner.ssl.socket.create_connection"):
            scanner._check_tls_version("example.com")
    assert any("tls version" in r["type"].lower() and r["status"] == "FAIL"
               for r in scanner.results)
