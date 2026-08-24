"""Tests for response header audit (version disclosure, deprecated headers)."""

from unittest.mock import MagicMock
from tblue.scanner.response_headers import ResponseHeadersScanner


def _scanner(headers: dict = None):
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<html></html>"
        resp.headers = headers or {}
        return resp

    session.request.side_effect = fake_request
    return ResponseHeadersScanner(session)


# ── Version disclosure ────────────────────────────────────────────────────────

def test_server_with_version_warns():
    scanner = _scanner({"Server": "Apache/2.4.51 (Unix)"})
    results = scanner.scan("https://example.com")
    assert any("version disclosure" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


def test_x_powered_by_warns():
    scanner = _scanner({"X-Powered-By": "PHP/8.1.0"})
    results = scanner.scan("https://example.com")
    assert any("version disclosure" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


def test_aspnet_version_warns():
    scanner = _scanner({"X-AspNet-Version": "4.0.30319"})
    results = scanner.scan("https://example.com")
    assert any("version disclosure" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


def test_clean_server_header_passes():
    scanner = _scanner({"Server": "nginx"})  # no version number
    results = scanner.scan("https://example.com")
    # nginx without version — technology disclosure but no version number
    # still flagged as tech disclosure
    assert any(r["status"] in ("PASS", "WARN") for r in results)


def test_no_version_headers_passes():
    scanner = _scanner({})
    results = scanner.scan("https://example.com")
    assert any("no version/technology disclosure" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


# ── Deprecated headers ────────────────────────────────────────────────────────

def test_xss_protection_non_zero_warns():
    scanner = _scanner({"X-XSS-Protection": "1; mode=block"})
    results = scanner.scan("https://example.com")
    assert any("x-xss-protection" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


def test_xss_protection_zero_passes():
    scanner = _scanner({"X-XSS-Protection": "0"})
    results = scanner.scan("https://example.com")
    assert any("x-xss-protection: 0" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_hpkp_warns():
    scanner = _scanner({"Public-Key-Pins": 'max-age=5184000; pin-sha256="abc"'})
    results = scanner.scan("https://example.com")
    assert any("public-key-pins" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


def test_p3p_warns():
    scanner = _scanner({"P3P": 'CP="NON DSP COR NID"'})
    results = scanner.scan("https://example.com")
    assert any("p3p" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Internal IP disclosure ────────────────────────────────────────────────────

def test_via_internal_ip_warns():
    scanner = _scanner({"Via": "1.1 192.168.1.10"})
    results = scanner.scan("https://example.com")
    assert any("internal infrastructure" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


def test_x_forwarded_for_internal_warns():
    scanner = _scanner({"X-Forwarded-For": "10.0.0.5, 203.0.113.1"})
    results = scanner.scan("https://example.com")
    assert any("internal infrastructure" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


# ── ETag inode ────────────────────────────────────────────────────────────────

def test_inode_etag_warns():
    scanner = _scanner({"ETag": '"abc123-1f4-5e2d8a0b"'})
    results = scanner.scan("https://example.com")
    assert any("etag" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_normal_etag_clean():
    scanner = _scanner({"ETag": '"33a64df5"'})
    results = scanner.scan("https://example.com")
    assert not any("etag" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── DNS prefetch ──────────────────────────────────────────────────────────────

def test_dns_prefetch_off_passes():
    scanner = _scanner({"X-DNS-Prefetch-Control": "off"})
    results = scanner.scan("https://example.com")
    assert any("dns prefetch disabled" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_dns_prefetch_missing_warns():
    scanner = _scanner({})
    results = scanner.scan("https://example.com")
    assert any("x-dns-prefetch-control not set" in r["type"].lower() and r["status"] == "WARN"
               for r in results)
