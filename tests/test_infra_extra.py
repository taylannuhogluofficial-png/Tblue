"""Extra branch coverage for tblue.scanner.infra."""

from unittest.mock import MagicMock, patch
from tblue.scanner.infra import InfraScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return InfraScanner(session)


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _404():
    r = MagicMock()
    r.status_code = 404
    r.text = ""
    r.headers = {}
    return r


def test_directory_listing_detected():
    """Branch: GET on probe path returns 200 with directory listing signature."""
    s = _scanner()
    def side(url, **kw):
        if "/uploads/" in url:
            return _resp(200, "Index of /uploads/ <a href='../'>Parent Directory</a>")
        return _404()
    s.http.get = MagicMock(side_effect=side)
    results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("directory" in r["type"].lower() or "listing" in r["type"].lower() for r in fails)


def test_html_artifact_response_is_skipped():
    """Branch: artifact path returns HTML page (false positive) → not flagged."""
    s = _scanner()
    def side(url, **kw):
        if ".git" in url or ".map" in url or ".vscode" in url or ".idea" in url or ".DS_Store" in url or ".env" in url:
            return _resp(200, "<!DOCTYPE html><html>Not found</html>")
        return _resp(200, "safe content")
    s.http.get = MagicMock(side_effect=side)
    results = s.scan(URL)
    # HTML responses are false-positive skipped
    git_fails = [r for r in results if ".git" in r.get("type", "").lower()]
    assert not git_fails


def test_openid_config_exposed_is_warn():
    """Branch: .well-known/openid-configuration returns OIDC JSON → WARN."""
    s = _scanner()
    def side(url, **kw):
        if "openid-configuration" in url:
            return _resp(200, '{"issuer":"https://example.com","authorization_endpoint":"..."}')
        return _404()
    s.http.get = MagicMock(side_effect=side)
    results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("openid" in r["type"].lower() for r in warns)


def test_referrer_policy_unsafe_url_is_warn():
    """Branch: Referrer-Policy: unsafe-url → WARN."""
    s = _scanner()
    s.http.get = MagicMock(return_value=_resp(200, "", {"Referrer-Policy": "unsafe-url"}))
    results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("unsafe-url" in r["type"].lower() or "referrer" in r["type"].lower() for r in warns)


def test_exception_during_dir_probe_continues():
    """Branch: exception on a dir probe path → silently continue."""
    s = _scanner()
    s.http.get = MagicMock(side_effect=ConnectionError("timeout"))
    results = s.scan(URL)
    # Should not raise; must return list
    assert isinstance(results, list)


def test_git_config_exposed_is_fail():
    """Branch: /.git/config returns content → FAIL."""
    s = _scanner()
    def side(url, **kw):
        if "/.git/config" in url:
            return _resp(200, "[core]\n\trepositoryformatversion = 0")
        return _404()
    s.http.get = MagicMock(side_effect=side)
    results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("git" in r["type"].lower() for r in fails)
