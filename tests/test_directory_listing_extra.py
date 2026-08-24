"""Extra branch coverage for tblue.scanner.directory_listing."""

from unittest.mock import MagicMock, patch
from tblue.scanner.directory_listing import DirectoryListingScanner

URL = "https://example.com"


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _scanner():
    session = MagicMock()
    return DirectoryListingScanner(session)


def test_all_dirs_404_returns_pass():
    """Branch: all directory probes return 404 — PASS."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(404, "")):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    assert all(r["status"] != "FAIL" for r in results)


def test_apache_listing_detected_fails():
    """Branch: directory returns Apache 'Index of /' listing — FAIL or WARN."""
    s = _scanner()
    listing_body = "<html><head><title>Index of /uploads/</title></head><body><h1>Index of /uploads/</h1></body></html>"

    def side_effect(url, **kwargs):
        if "/uploads/" in url:
            return _resp(200, listing_body)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad
    assert any("listing" in r["type"].lower() or "directory" in r["type"].lower() for r in bad)


def test_vcs_git_directory_exposed_fails():
    """Branch: /.git/ exposed — FAIL (VCS special case)."""
    s = _scanner()
    git_body = '<html><h1>Directory listing for /.git/</h1><a href="..">..</a></html>'

    def side_effect(url, **kwargs):
        if "/.git/" in url:
            return _resp(200, git_body)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any(".git" in r.get("url", "") or "vcs" in r["type"].lower()
               or "git" in r["type"].lower() for r in fails)


def test_non_200_status_skipped():
    """Branch: probe returns 403 Forbidden — not counted as directory listing."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(403, "Forbidden")):
        results = s.scan(URL)
    assert isinstance(results, list)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not fails


def test_nginx_listing_pattern_detected():
    """Branch: Nginx 'Parent Directory' link pattern triggers FAIL or WARN."""
    s = _scanner()
    nginx_body = "<html><body><a href='..'>Parent Directory</a><a href='file.txt'>file.txt</a></body></html>"

    def side_effect(url, **kwargs):
        if "/backup/" in url:
            return _resp(200, nginx_body)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad


def test_none_response_for_probe_is_skipped():
    """Branch: http.get returns None for a probe — no exception, continues."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert any(r["status"] == "PASS" for r in results)
