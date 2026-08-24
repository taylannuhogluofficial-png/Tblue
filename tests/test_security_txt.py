"""
Tests for security.txt scanner.
"""

import pytest
from unittest.mock import MagicMock
from tblue.scanner.security_txt import SecurityTxtScanner


def make_scanner(responses: dict = None) -> SecurityTxtScanner:
    """
    responses: {url_suffix: (status_code, body, content_type)}
    Unmatched paths return 404.
    """
    responses = responses or {}
    session   = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        for suffix, (code, body, ct) in responses.items():
            if url.endswith(suffix) or suffix in url:
                resp.status_code = code
                resp.text        = body
                resp.headers     = {"content-type": ct}
                resp.url         = url
                return resp
        resp.status_code = 404
        resp.text        = "Not Found"
        resp.headers     = {"content-type": "text/plain"}
        resp.url         = url
        return resp

    session.request.side_effect = fake_request
    return SecurityTxtScanner(session)


_VALID_SECURITY_TXT = """\
Contact: mailto:security@example.com
Expires: 2027-01-01T00:00:00.000Z
Policy: https://example.com/security-policy
Encryption: https://example.com/pgp-key.txt
Acknowledgments: https://example.com/hall-of-fame
"""

_MINIMAL_SECURITY_TXT = """\
Contact: mailto:security@example.com
Expires: 2027-01-01T00:00:00.000Z
"""

_INCOMPLETE_SECURITY_TXT = """\
Contact: mailto:security@example.com
"""


# ── Missing ───────────────────────────────────────────────────────────────────

def test_missing_security_txt_warns():
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("missing" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Valid ─────────────────────────────────────────────────────────────────────

def test_valid_security_txt_passes():
    scanner = make_scanner({"/.well-known/security.txt": (200, _VALID_SECURITY_TXT, "text/plain")})
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_minimal_security_txt_passes():
    scanner = make_scanner({"/.well-known/security.txt": (200, _MINIMAL_SECURITY_TXT, "text/plain")})
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_fallback_to_root_security_txt():
    scanner = make_scanner({"/security.txt": (200, _VALID_SECURITY_TXT, "text/plain")})
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


# ── Incomplete ────────────────────────────────────────────────────────────────

def test_missing_expires_warns():
    scanner = make_scanner({"/.well-known/security.txt": (200, _INCOMPLETE_SECURITY_TXT, "text/plain")})
    results = scanner.scan("https://example.com")
    assert any("incomplete" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── HTML false positive avoidance ─────────────────────────────────────────────

def test_html_404_page_treated_as_missing():
    html_body = "<html><body><h1>Page Not Found</h1></body></html>"
    scanner   = make_scanner({"/.well-known/security.txt": (200, html_body, "text/html")})
    results   = scanner.scan("https://example.com")
    assert any("missing" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Detail quality ────────────────────────────────────────────────────────────

def test_missing_result_has_fix_guidance():
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    warn    = next(r for r in results if r["status"] == "WARN")
    assert "contact" in warn["detail"].lower()
    assert "fix" in warn["detail"].lower()


def test_no_contact_field_skips_path_and_returns_warn():
    # security.txt present but no Contact: field → scanner skips it → treated as missing
    body_no_contact = "Expires: 2027-01-01T00:00:00.000Z\nPolicy: https://example.com/policy\n"
    scanner = make_scanner({"/.well-known/security.txt": (200, body_no_contact, "text/plain")})
    results = scanner.scan("https://example.com")
    # No Contact found in either path → _find returns (None, None) → missing WARN
    assert any("missing" in r["type"].lower() and r["status"] == "WARN" for r in results)
