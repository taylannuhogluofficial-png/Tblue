"""Tests for Permissions-Policy deep audit."""

from unittest.mock import MagicMock
from tblue.scanner.permissions_policy import PermissionsPolicyScanner


def _scanner(pp_header="", fp_header=""):
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<html></html>"
        resp.headers = {}
        if pp_header:
            resp.headers["Permissions-Policy"] = pp_header
        if fp_header:
            resp.headers["Feature-Policy"] = fp_header
        return resp

    session.request.side_effect = fake_request
    return PermissionsPolicyScanner(session)


# ── No header → WARN ──────────────────────────────────────────────────────────

def test_no_header_warns():
    scanner = _scanner()
    results = scanner.scan("https://example.com")
    assert any("header absent" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── camera=() blocked ────────────────────────────────────────────────────────

def test_camera_blocked_passes():
    scanner = _scanner(pp_header="camera=()")
    results = scanner.scan("https://example.com")
    assert any("camera blocked" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_microphone_blocked_passes():
    scanner = _scanner(pp_header="microphone=()")
    results = scanner.scan("https://example.com")
    assert any("microphone blocked" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_geolocation_blocked_passes():
    scanner = _scanner(pp_header="geolocation=()")
    results = scanner.scan("https://example.com")
    assert any("geolocation blocked" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_payment_blocked_passes():
    scanner = _scanner(pp_header="payment=()")
    results = scanner.scan("https://example.com")
    assert any("payment blocked" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ── camera=(self) ─────────────────────────────────────────────────────────────

def test_camera_self_passes():
    scanner = _scanner(pp_header="camera=(self)")
    results = scanner.scan("https://example.com")
    assert any("camera restricted to self" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


# ── camera=* wildcard → FAIL ─────────────────────────────────────────────────

def test_camera_wildcard_fails():
    scanner = _scanner(pp_header="camera=*")
    results = scanner.scan("https://example.com")
    assert any("camera" in r["type"].lower() and "all origins" in r["type"].lower()
               and r["status"] == "FAIL" for r in results)


def test_microphone_wildcard_fails():
    scanner = _scanner(pp_header="microphone=*")
    results = scanner.scan("https://example.com")
    assert any("microphone" in r["type"].lower() and "all origins" in r["type"].lower()
               and r["status"] == "FAIL" for r in results)


def test_payment_wildcard_fails():
    scanner = _scanner(pp_header="payment=*")
    results = scanner.scan("https://example.com")
    assert any("payment" in r["type"].lower() and "all origins" in r["type"].lower()
               and r["status"] == "FAIL" for r in results)


# ── camera not in policy → WARN for sensitive ─────────────────────────────────

def test_camera_not_in_policy_warns():
    scanner = _scanner(pp_header="autoplay=()")
    results = scanner.scan("https://example.com")
    assert any("camera not restricted" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


# ── Deprecated Feature-Policy only → WARN ────────────────────────────────────

def test_feature_policy_only_warns():
    scanner = _scanner(fp_header="camera 'none'; microphone 'none'")
    results = scanner.scan("https://example.com")
    assert any("deprecated" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Full ideal policy ─────────────────────────────────────────────────────────

def test_full_restrictive_policy_no_fails():
    scanner = _scanner(pp_header=(
        "camera=(), microphone=(), geolocation=(), payment=(), "
        "usb=(), serial=(), bluetooth=(), display-capture=()"
    ))
    results = scanner.scan("https://example.com")
    assert not any(r["status"] == "FAIL" for r in results)
    assert any(r["status"] == "PASS" for r in results)


# ── Network error → empty ─────────────────────────────────────────────────────

def test_network_error_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("timeout")
    scanner = PermissionsPolicyScanner(session)
    results = scanner.scan("https://example.com")
    assert results == []
