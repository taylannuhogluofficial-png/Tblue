"""Tests for tblue.scanner.directory_listing — DirectoryListingScanner."""

import pytest
from unittest.mock import MagicMock, patch

from tblue.scanner.directory_listing import (
    DirectoryListingScanner,
    _is_listing,
    _base_url,
)

URL = "https://example.com"


def _make_scanner():
    session = MagicMock()
    return DirectoryListingScanner(session)


def _mock_resp(status=200, body=""):
    r = MagicMock()
    r.status_code = status
    r.text = body
    return r


# ── helpers ───────────────────────────────────────────────────────────────────

def test_base_url():
    assert _base_url("https://example.com/a/b") == "https://example.com"


def test_is_listing_apache():
    assert _is_listing("<title>Index of /uploads</title>")


def test_is_listing_nginx():
    assert _is_listing("<h1>Directory: /</h1>")


def test_is_listing_iis():
    assert _is_listing("[To Parent Directory]")


def test_is_listing_python_http():
    assert _is_listing("Directory listing for /tmp")


def test_is_listing_parent_link():
    assert _is_listing('<a href="..">Parent Directory</a>')


def test_is_listing_false_for_normal_page():
    assert not _is_listing("<html><body>Hello world</body></html>")


# ── scan() — none exposed ────────────────────────────────────────────────────

def test_scan_all_404():
    scanner = _make_scanner()
    with patch.object(scanner.http, "get", return_value=_mock_resp(status=404)):
        results = scanner.scan(URL)
    assert len(results) == 1
    assert results[0]["status"] == "PASS"


def test_scan_none_response():
    scanner = _make_scanner()
    with patch.object(scanner.http, "get", return_value=None):
        results = scanner.scan(URL)
    assert results[0]["status"] == "PASS"


def test_scan_200_but_not_listing():
    scanner = _make_scanner()
    with patch.object(scanner.http, "get", return_value=_mock_resp(200, "<html>Normal page</html>")):
        results = scanner.scan(URL)
    assert results[0]["status"] == "PASS"


# ── scan() — directory listing found (WARN) ───────────────────────────────────

def test_scan_listing_found_warn():
    scanner = _make_scanner()
    listing_body = "<title>Index of /uploads</title>"

    def side_effect(url, **kwargs):
        if "/uploads/" in url:
            return _mock_resp(200, listing_body)
        return _mock_resp(404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert len(warns) >= 1
    assert "uploads" in warns[0]["type"]


def test_scan_multiple_listings():
    scanner = _make_scanner()
    listing_body = "<title>Index of /</title>"
    _listing_urls = {
        "https://example.com/uploads/",
        "https://example.com/logs/",
    }

    def side_effect(url, **kwargs):
        if url in _listing_urls:
            return _mock_resp(200, listing_body)
        return _mock_resp(404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert len(warns) == 2


# ── scan() — VCS directory exposed (FAIL) ────────────────────────────────────

def test_scan_git_exposed():
    scanner = _make_scanner()
    git_body = "Index of /.git\n<a href='HEAD'>HEAD</a>"

    def side_effect(url, **kwargs):
        if "/.git/" in url:
            return _mock_resp(200, git_body)
        return _mock_resp(404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert len(fails) >= 1
    assert ".git" in fails[0]["type"]


def test_scan_svn_exposed():
    scanner = _make_scanner()
    svn_body = "Directory listing for /.svn"

    def side_effect(url, **kwargs):
        if "/.svn/" in url:
            return _mock_resp(200, svn_body)
        return _mock_resp(404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any(".svn" in f["type"] for f in fails)


# ── exception handling ────────────────────────────────────────────────────────

def test_scan_exception_continues():
    scanner = _make_scanner()
    calls = {"n": 0}

    def side_effect(url, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("timeout")
        return _mock_resp(404)

    with patch.object(scanner.http, "get", side_effect=side_effect):
        results = scanner.scan(URL)
    assert results[0]["status"] == "PASS"
