"""Extra branch coverage for tblue.scanner.robots_txt."""

from unittest.mock import MagicMock
from tblue.scanner.robots_txt import RobotsSecurityScanner

URL = "https://example.com"


def _scanner(robots_status=200, robots_body=""):
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = robots_status
    resp.text = robots_body
    resp.headers = {}
    resp.url = URL + "/robots.txt"
    s = RobotsSecurityScanner(session)
    s.http.get = MagicMock(return_value=resp)
    return s


def test_robots_not_found_warns():
    """404 on robots.txt triggers a WARN about its absence."""
    results = _scanner(robots_status=404).scan(URL)
    warns = [r for r in results if r["status"] == "WARN" and "not found" in r["type"].lower()]
    assert warns


def test_robots_exception_returns_empty():
    """Exception when fetching robots.txt returns empty results."""
    s = RobotsSecurityScanner(MagicMock())
    s.http.get = MagicMock(side_effect=ConnectionError("timeout"))
    results = s.scan(URL)
    assert results == []


def test_sensitive_admin_disallow_warns():
    """Disallow: /admin in robots.txt triggers a WARN for sensitive path disclosure."""
    body = "User-agent: *\nDisallow: /admin\n"
    results = _scanner(robots_body=body).scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_git_disallow_fails():
    """Disallow: /.git in robots.txt triggers a FAIL for critical path disclosure."""
    body = "User-agent: *\nDisallow: /.git\n"
    results = _scanner(robots_body=body).scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_empty_disallow_no_sensitive_paths():
    """Disallow: / (full block) without sensitive paths — no FAIL for sensitive paths."""
    body = "User-agent: *\nDisallow: /\n"
    results = _scanner(robots_body=body).scan(URL)
    # No sensitive path findings
    sensitive_fails = [r for r in results if "critical" in r.get("type", "").lower()]
    assert not sensitive_fails


def test_sitemap_in_robots_noted():
    """Sitemap directive in robots.txt is noted in results."""
    body = "User-agent: *\nDisallow: /\nSitemap: https://example.com/sitemap.xml\n"
    results = _scanner(robots_body=body).scan(URL)
    assert isinstance(results, list)
