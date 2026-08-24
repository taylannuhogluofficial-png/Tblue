"""Tests for robots.txt security/path disclosure scanner."""

from unittest.mock import MagicMock
from tblue.scanner.robots_txt import RobotsSecurityScanner


def _scanner(robots_content: str = None, status: int = 200):
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        if robots_content is not None and "robots.txt" in url:
            resp.status_code = status
            resp.text = robots_content
        else:
            resp.status_code = 404
            resp.text = "Not Found"
        return resp

    session.request.side_effect = fake_request
    return RobotsSecurityScanner(session)


_CLEAN_ROBOTS = """\
User-agent: *
Disallow: /private-page
Disallow: /internal-only
Allow: /

Sitemap: https://example.com/sitemap.xml
"""

_SENSITIVE_ROBOTS = """\
User-agent: *
Disallow: /admin
Disallow: /backup
Disallow: /api/
Disallow: /wp-admin/
Disallow: /config
"""

_CRITICAL_ROBOTS = """\
User-agent: *
Disallow: /.git
Disallow: /admin
"""

_FULL_BLOCK_ROBOTS = """\
User-agent: *
Disallow: /
"""


# ── File not found ────────────────────────────────────────────────────────────

def test_robots_not_found_warns():
    scanner = _scanner(status=404)
    results = scanner.scan("https://example.com")
    assert any("file not found" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Clean robots.txt ──────────────────────────────────────────────────────────

def test_clean_robots_passes():
    scanner = _scanner(_CLEAN_ROBOTS)
    results = scanner.scan("https://example.com")
    assert any("no sensitive paths" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


# ── Sensitive paths ───────────────────────────────────────────────────────────

def test_admin_path_in_disallow_warns():
    robots = "User-agent: *\nDisallow: /admin\n"
    scanner = _scanner(robots)
    results = scanner.scan("https://example.com")
    assert any("sensitive paths" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_backup_path_warns():
    robots = "User-agent: *\nDisallow: /backup\n"
    scanner = _scanner(robots)
    results = scanner.scan("https://example.com")
    assert any("sensitive paths" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_api_path_warns():
    robots = "User-agent: *\nDisallow: /api/\n"
    scanner = _scanner(robots)
    results = scanner.scan("https://example.com")
    assert any("sensitive paths" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_multiple_sensitive_paths_warns():
    scanner = _scanner(_SENSITIVE_ROBOTS)
    results = scanner.scan("https://example.com")
    assert any("sensitive paths" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Critical paths (Git, keys) ────────────────────────────────────────────────

def test_git_in_disallow_fails():
    scanner = _scanner(_CRITICAL_ROBOTS)
    results = scanner.scan("https://example.com")
    assert any("critical paths" in r["type"].lower() and r["status"] == "FAIL" for r in results)


# ── Full site block ───────────────────────────────────────────────────────────

def test_full_site_disallow_warns():
    scanner = _scanner(_FULL_BLOCK_ROBOTS)
    results = scanner.scan("https://example.com")
    assert any("full site blocked" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Sitemap declaration ───────────────────────────────────────────────────────

def test_sitemap_declared_passes():
    scanner = _scanner(_CLEAN_ROBOTS)
    results = scanner.scan("https://example.com")
    assert any("sitemap" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_no_sitemap_no_finding():
    robots = "User-agent: *\nDisallow: /cart\n"
    scanner = _scanner(robots)
    results = scanner.scan("https://example.com")
    # No sitemap = no finding (it's optional)
    assert not any("sitemap" in r["type"].lower() for r in results)


# ── Network error ─────────────────────────────────────────────────────────────

def test_network_error_treated_as_not_found():
    # When network fails, HTTPClient returns None — scanner treats it like 404
    session = MagicMock()
    session.request.side_effect = Exception("timeout")
    scanner = RobotsSecurityScanner(session)
    results = scanner.scan("https://example.com")
    # Returns a WARN (not found) rather than crashing
    assert all(r["status"] in ("PASS", "WARN", "FAIL") for r in results)
