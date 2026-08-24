"""
Tests for access control scanner (admin page discovery, robots.txt leakage).
"""

import pytest
from unittest.mock import MagicMock
from tblue.scanner.access_control import AccessControlScanner


def make_scanner(paths: dict = None) -> AccessControlScanner:
    """
    Build an AccessControlScanner with a mocked session.

    paths: dict mapping URL path suffix → (status_code, body)
    Any path not in paths returns 404.
    """
    paths = paths or {}
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        for suffix, (code, body) in paths.items():
            if url.endswith(suffix):
                resp = MagicMock()
                resp.status_code = code
                resp.text = body
                resp.url  = url
                return resp
        # Default: 404
        resp = MagicMock()
        resp.status_code = 404
        resp.text = "<html><body>Not Found</body></html>"
        resp.url  = url
        return resp

    session.request.side_effect = fake_request
    return AccessControlScanner(session)


# ── robots.txt leakage ────────────────────────────────────────────────────────

def test_robots_admin_path_warns():
    robots_body = "User-agent: *\nDisallow: /admin\nDisallow: /wp-admin\n"
    scanner = make_scanner({"/robots.txt": (200, robots_body)})
    results = scanner.scan("https://example.com")
    assert any("robots.txt" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_robots_no_admin_path_not_flagged():
    robots_body = "User-agent: *\nDisallow: /private/\nDisallow: /temp/\n"
    scanner = make_scanner({"/robots.txt": (200, robots_body)})
    results = scanner.scan("https://example.com")
    robots_warns = [r for r in results if "robots.txt" in r["type"].lower() and r["status"] == "WARN"]
    assert len(robots_warns) == 0


def test_robots_not_found_not_flagged():
    scanner = make_scanner()  # all 404
    results = scanner.scan("https://example.com")
    robots_warns = [r for r in results if "robots.txt" in r["type"].lower() and r["status"] == "WARN"]
    assert len(robots_warns) == 0


# ── Admin path probing ────────────────────────────────────────────────────────

def test_open_admin_panel_fails():
    admin_body = "<html><body><h1>Admin Dashboard</h1><p>Welcome, admin</p></body></html>"
    scanner = make_scanner({"/admin": (200, admin_body)})
    results = scanner.scan("https://example.com")
    assert any("admin interface publicly accessible" in r["type"].lower() and r["status"] == "FAIL"
               for r in results)


def test_admin_login_page_warns():
    login_body = (
        "<html><body><form><input name='username'><input type='password' name='pwd'>"
        "<button>Log in</button></form></body></html>"
    )
    scanner = make_scanner({"/admin": (200, login_body)})
    results = scanner.scan("https://example.com")
    assert any("admin login page discoverable" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


def test_admin_returns_403_passes():
    scanner = make_scanner({"/admin": (403, "Forbidden"), "/wp-admin": (403, "Forbidden")})
    results = scanner.scan("https://example.com")
    # Should get PASS for admin exposure check (no open panels)
    pass_results = [r for r in results if "admin" in r["type"].lower() and r["status"] == "PASS"]
    assert len(pass_results) > 0


def test_no_admin_pages_passes():
    scanner = make_scanner()  # all 404
    results = scanner.scan("https://example.com")
    pass_results = [r for r in results if "admin" in r["type"].lower() and r["status"] == "PASS"]
    assert len(pass_results) > 0


def test_wp_admin_exposed_fails():
    wp_body = "<html><body><h1>WordPress Admin</h1><p>Welcome to the admin dashboard</p></body></html>"
    scanner = make_scanner({"/wp-admin": (200, wp_body)})
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "FAIL" and "admin" in r["type"].lower() for r in results)


def test_robots_returns_non_200_not_flagged():
    # robots.txt with 500 error — should return early without flagging
    scanner = make_scanner({"/robots.txt": (500, "Internal Server Error")})
    results = scanner.scan("https://example.com")
    robots_warns = [r for r in results if "robots.txt" in r["type"].lower() and r["status"] == "WARN"]
    assert len(robots_warns) == 0


def test_admin_path_non_200_non_404_skipped():
    # Status 500 → code != 200 branch → continue (not added to any bucket)
    scanner = make_scanner({"/admin": (500, "Server Error")})
    results = scanner.scan("https://example.com")
    fail_results = [r for r in results if "publicly accessible" in r["type"].lower()]
    assert len(fail_results) == 0


def test_admin_panel_without_auth_form_is_open():
    # 200 with dashboard keywords but no password input → found_open
    panel_body = "<html><body><h1>Control Panel</h1><p>Manage site settings here</p></body></html>"
    scanner = make_scanner({"/admin": (200, panel_body)})
    results = scanner.scan("https://example.com")
    assert any("publicly accessible" in r["type"].lower() and r["status"] == "FAIL"
               for r in results)
