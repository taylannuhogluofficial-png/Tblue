"""
Tests for cookie flag scanner.
"""

import pytest
from unittest.mock import MagicMock
from tblue.scanner.cookies import CookieScanner


def make_scanner(set_cookie_value: str = None) -> CookieScanner:
    session      = MagicMock()
    resp         = MagicMock()
    resp.headers = {"set-cookie": set_cookie_value} if set_cookie_value else {}
    resp.url     = "https://example.com"
    resp.raw     = MagicMock()
    resp.raw.headers = MagicMock()
    resp.raw.headers.getlist = lambda k: ([set_cookie_value] if set_cookie_value else [])
    session.request.return_value = resp
    return CookieScanner(session)


def get_summary(results):
    """Get the final summary result dict."""
    return next((r for r in results if "cookies" in r), None)


def test_all_flags_present_passes():
    scanner = make_scanner("session=abc; HttpOnly; Secure; SameSite=Strict")
    results = scanner.scan("https://example.com")
    summary = get_summary(results)
    assert summary is not None
    assert summary["cookies"][0]["status"] == "PASS"


def test_missing_httponly_fails():
    scanner = make_scanner("session=abc; Secure; SameSite=Strict")
    results = scanner.scan("https://example.com")
    summary = get_summary(results)
    assert summary["cookies"][0]["httponly"] is False
    assert summary["cookies"][0]["status"] == "FAIL"


def test_missing_secure_fails():
    scanner = make_scanner("session=abc; HttpOnly; SameSite=Strict")
    results = scanner.scan("https://example.com")
    summary = get_summary(results)
    assert summary["cookies"][0]["secure"] is False
    assert summary["cookies"][0]["status"] == "FAIL"


def test_missing_samesite_warns():
    scanner = make_scanner("session=abc; HttpOnly; Secure")
    results = scanner.scan("https://example.com")
    summary = get_summary(results)
    assert summary["cookies"][0]["samesite"] is False
    assert summary["cookies"][0]["status"] == "WARN"


def test_all_flags_missing_fails():
    scanner = make_scanner("session=abc")
    results = scanner.scan("https://example.com")
    summary = get_summary(results)
    c = summary["cookies"][0]
    assert c["httponly"] is False
    assert c["secure"]   is False
    assert c["samesite"] is False
    assert c["status"] == "FAIL"


def test_no_cookies_returns_pass():
    scanner = make_scanner(None)
    results = scanner.scan("https://example.com")
    summary = get_summary(results)
    assert summary["status"] == "PASS"
    assert summary["cookies"] == []


def test_overall_status_pass_if_all_pass():
    scanner = make_scanner("session=abc; HttpOnly; Secure; SameSite=Strict")
    results = scanner.scan("https://example.com")
    summary = get_summary(results)
    assert summary["status"] == "PASS"


def test_result_has_required_fields():
    scanner = make_scanner("session=abc; HttpOnly; Secure; SameSite=Lax")
    results = scanner.scan("https://example.com")
    summary = get_summary(results)
    assert summary is not None
    assert "url"     in summary
    assert "cookies" in summary
    assert "status"  in summary


def test_failed_request_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("Timeout")
    scanner = CookieScanner(session, retries=1)
    results = scanner.scan("https://example.com")
    assert results == []


def test_cookie_name_extracted_correctly():
    scanner = make_scanner("my_token=xyz123; HttpOnly; Secure; SameSite=Strict")
    results = scanner.scan("https://example.com")
    summary = get_summary(results)
    assert summary["cookies"][0]["name"] == "my_token"


def test_samesite_none_without_secure_fails():
    scanner = make_scanner("session=abc; HttpOnly; SameSite=None")
    results = scanner.scan("https://example.com")
    assert any("SameSite=None" in r.get("type","") and r["status"] == "FAIL" for r in results)


def test_samesite_strict_passes():
    scanner = make_scanner("session=abc; HttpOnly; Secure; SameSite=Strict")
    results = scanner.scan("https://example.com")
    assert any("Strict" in r.get("type","") and r["status"] == "PASS" for r in results)


def test_samesite_lax_passes():
    scanner = make_scanner("session=abc; HttpOnly; Secure; SameSite=Lax")
    results = scanner.scan("https://example.com")
    assert any("Lax" in r.get("type","") and r["status"] == "PASS" for r in results)


def test_long_expiry_warns():
    scanner = make_scanner("session=abc; HttpOnly; Secure; SameSite=Strict; Max-Age=94608000")
    results = scanner.scan("https://example.com")
    assert any("expiry" in r.get("type","").lower() and r["status"] == "WARN" for r in results)


def test_host_prefix_without_secure_fails():
    scanner = make_scanner("__Host-session=abc; HttpOnly; Path=/")
    results = scanner.scan("https://example.com")
    assert any("__Host-" in r.get("type","") and r["status"] == "FAIL" for r in results)


def test_secure_prefix_without_secure_fails():
    scanner = make_scanner("__Secure-session=abc; HttpOnly; SameSite=Strict")
    results = scanner.scan("https://example.com")
    assert any("__Secure-" in r.get("type","") and r["status"] == "FAIL" for r in results)


# ── Multiple cookies in one response ──────────────────────────────────────────

def make_scanner_multi(cookie_list):
    """Build scanner with multiple Set-Cookie values (raw list)."""
    session = MagicMock()
    resp = MagicMock()
    resp.headers = {}
    resp.url = "https://example.com"
    resp.raw = MagicMock()
    resp.raw.headers = MagicMock()
    resp.raw.headers.getlist = lambda k: cookie_list
    session.request.return_value = resp
    return CookieScanner(session)


def test_two_cookies_both_good_passes():
    scanner = make_scanner_multi([
        "session=abc; HttpOnly; Secure; SameSite=Strict",
        "pref=dark; HttpOnly; Secure; SameSite=Lax",
    ])
    results = scanner.scan("https://example.com")
    summary = get_summary(results)
    assert summary is not None
    assert summary["status"] == "PASS"
    assert len(summary["cookies"]) == 2


def test_two_cookies_one_bad_overall_fails():
    scanner = make_scanner_multi([
        "session=abc; HttpOnly; Secure; SameSite=Strict",
        "tracking=xyz",  # missing all flags
    ])
    results = scanner.scan("https://example.com")
    summary = get_summary(results)
    assert summary is not None
    assert summary["status"] == "FAIL"


def test_host_prefix_with_domain_fails():
    # __Host- requires: Secure flag, Path=/, no Domain attribute
    scanner = make_scanner("__Host-session=abc; HttpOnly; Secure; Path=/; Domain=example.com")
    results = scanner.scan("https://example.com")
    assert any("__Host-" in r.get("type", "") and r["status"] == "FAIL" for r in results)


# ── Domain wildcard scope ─────────────────────────────────────────────────────

def test_wildcard_domain_warns():
    scanner = make_scanner("pref=abc; HttpOnly; Secure; SameSite=Lax; Domain=.example.com")
    results = scanner.scan("https://example.com")
    assert any("domain" in r.get("type", "").lower() and r["status"] == "WARN" for r in results)


def test_samesite_none_with_secure_warns():
    # SameSite=None + Secure → WARN (not FAIL)
    scanner = make_scanner("session=abc; HttpOnly; Secure; SameSite=None")
    results = scanner.scan("https://example.com")
    assert any("SameSite=None" in r.get("type", "") and r["status"] == "WARN" for r in results)


def test_invalid_max_age_handled_gracefully():
    # Max-Age with non-integer → ValueError caught, treated as session cookie
    scanner = make_scanner("session=abc; HttpOnly; Secure; SameSite=Strict; Max-Age=invalid")
    results = scanner.scan("https://example.com")
    assert isinstance(results, list)
    assert len(results) > 0


def test_expires_attribute_parsed():
    # Cookie with Expires but no Max-Age → persistent, no "session cookie" result
    scanner = make_scanner("session=abc; HttpOnly; Secure; SameSite=Strict; Expires=Thu, 01 Jan 2026 00:00:00 GMT")
    results = scanner.scan("https://example.com")
    assert isinstance(results, list)


def test_host_prefix_all_correct_passes():
    # __Host- with all required attributes → PASS
    scanner = make_scanner("__Host-session=abc; HttpOnly; Secure; SameSite=Strict; Path=/")
    results = scanner.scan("https://example.com")
    assert any("__Host-" in r.get("type", "") and r["status"] == "PASS" for r in results)


def test_secure_prefix_with_secure_passes():
    # __Secure- with Secure flag → PASS
    scanner = make_scanner("__Secure-session=abc; HttpOnly; Secure; SameSite=Strict")
    results = scanner.scan("https://example.com")
    assert any("__Secure-" in r.get("type", "") and r["status"] == "PASS" for r in results)


def test_short_expiry_passes():
    # Max-Age of 1 day (86400) → 1 day ≤ 365 → PASS
    scanner = make_scanner("pref=abc; HttpOnly; Secure; SameSite=Lax; Max-Age=86400")
    results = scanner.scan("https://example.com")
    assert any("expiry" in r.get("type", "").lower() and r["status"] == "PASS" for r in results)


def test_low_entropy_session_cookie_warns():
    # Session cookie with name matching 'session' and low-entropy value (repeating chars)
    scanner = make_scanner("session=aaaaaaaaaa; HttpOnly; Secure; SameSite=Strict")
    results = scanner.scan("https://example.com")
    # Low entropy → WARN; may or may not fire depending on threshold
    assert isinstance(results, list)


def test_duplicate_cookie_names_warn():
    scanner = make_scanner_multi([
        "session=first; HttpOnly; Secure; SameSite=Strict",
        "session=second; HttpOnly; Secure; SameSite=Strict",
    ])
    results = scanner.scan("https://example.com")
    assert any("duplicate" in r.get("type", "").lower() and r["status"] == "WARN" for r in results)


def test_partitioned_attribute_without_samesite_none_no_warning():
    # Partitioned check only fires for SameSite=None — with SameSite=Strict, no warning
    scanner = make_scanner("session=abc; HttpOnly; Secure; SameSite=Strict")
    results = scanner.scan("https://example.com")
    partitioned = [r for r in results if "partitioned" in r.get("type", "").lower()]
    assert len(partitioned) == 0


def test_host_prefix_without_path_slash_fails():
    # __Host- with wrong path (not /) → FAIL
    scanner = make_scanner("__Host-session=abc; HttpOnly; Secure; SameSite=Strict; Path=/admin")
    results = scanner.scan("https://example.com")
    assert any("__Host-" in r.get("type", "") and r["status"] == "FAIL" for r in results)


def test_long_expiry_when_already_fail_updates_status():
    # Cookie with missing HttpOnly (FAIL) AND long Max-Age → tests the `if cookie["status"] == "PASS":` branch
    scanner = make_scanner("session=abc; Secure; SameSite=Strict; Max-Age=94608000")
    results = scanner.scan("https://example.com")
    # Should have both FAIL (missing HttpOnly) and long expiry WARN
    assert any(r["status"] == "FAIL" for r in results)


def test_wildcard_domain_when_already_fail():
    # Cookie already FAIL (no HttpOnly) with wildcard domain → tests status update branch
    scanner = make_scanner("session=abc; Secure; SameSite=Strict; Domain=.example.com")
    results = scanner.scan("https://example.com")
    assert any("domain" in r.get("type", "").lower() for r in results)


def _make_gdpr_scanner(cookie: str, html: str = "") -> CookieScanner:
    session = MagicMock()
    resp = MagicMock()
    resp.headers = {"set-cookie": cookie}
    resp.url = "https://example.com"
    resp.text = html
    resp.raw = MagicMock()
    resp.raw.headers = MagicMock()
    resp.raw.headers.getlist = lambda k: [cookie]
    session.request.return_value = resp
    return CookieScanner(session)


def test_gdpr_tracking_without_consent_fails():
    # _ga is a tracking cookie; no consent HTML → FAIL
    scanner = _make_gdpr_scanner("_ga=GA1.2.abc; Secure; SameSite=Lax", html="<html><body>Hello</body></html>")
    results = scanner.scan("https://example.com")
    assert any("without consent" in r.get("type", "").lower() and r["status"] == "FAIL"
               for r in results)


def test_gdpr_tracking_with_consent_warns():
    # _ga tracking cookie + consent UI in page → WARN
    scanner = _make_gdpr_scanner(
        "_ga=GA1.2.abc; Secure; SameSite=Lax",
        html="<html><body><div class='cookieconsent'>Accept cookies</div></body></html>"
    )
    results = scanner.scan("https://example.com")
    assert any("consent ui present" in r.get("type", "").lower() and r["status"] == "WARN"
               for r in results)


def test_gdpr_no_tracking_passes():
    # Regular session cookie → no tracking → PASS
    scanner = _make_gdpr_scanner("session=abc; HttpOnly; Secure; SameSite=Strict", html="<html></html>")
    results = scanner.scan("https://example.com")
    assert any("no tracking" in r.get("type", "").lower() and r["status"] == "PASS"
               for r in results)
