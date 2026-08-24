"""Extra branch coverage for tblue.scanner.subdomain_takeover."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.subdomain_takeover import (
    SubdomainTakeoverScanner, _import_dns, _follow_cname
)


def test_import_dns_available():
    result = _import_dns()
    assert result is None or hasattr(result, "resolve")


def test_scan_returns_empty_list():
    session = MagicMock()
    s = SubdomainTakeoverScanner(session)
    assert s.scan("https://example.com") == []


def test_scan_subdomains_no_dns_skips():
    session = MagicMock()
    s = SubdomainTakeoverScanner(session)
    with patch("tblue.scanner.subdomain_takeover._import_dns", return_value=None):
        results = s.scan_subdomains(["sub.example.com"], "https://example.com")
    assert results == []


def test_check_subdomain_http_exception_returns_none():
    session = MagicMock()
    s = SubdomainTakeoverScanner(session)

    resolver = MagicMock()
    # Make CNAME follow succeed
    resolver.resolve.return_value = MagicMock()
    resolver.resolve.return_value.__getitem__ = lambda self, idx: MagicMock(
        target=MagicMock(__str__=lambda self: "xyz.github.io.")
    )

    # http.get raises exception
    s.http.get = MagicMock(side_effect=ConnectionError("refused"))

    # _follow_cname needs to return something matching the github fingerprint
    with patch("tblue.scanner.subdomain_takeover._follow_cname",
               return_value="xyz.github.io"):
        result = s._check_subdomain("old.example.com", resolver)
    # If HTTP probe fails (exception), returns None
    assert result is None


def test_check_subdomain_body_matches_takeover():
    session = MagicMock()
    s = SubdomainTakeoverScanner(session)
    resolver = MagicMock()

    resp = MagicMock()
    resp.text = "There isn't a GitHub Pages site here."
    s.http.get = MagicMock(return_value=resp)

    with patch("tblue.scanner.subdomain_takeover._follow_cname",
               return_value="user.github.io"):
        result = s._check_subdomain("abandoned.example.com", resolver)

    assert result is not None
    assert result["status"] in ("FAIL", "WARN")


def test_follow_cname_max_depth_returns_none():
    resolver = MagicMock()
    resolver.resolve.return_value = MagicMock()
    # Each call returns another CNAME — should terminate at depth=10
    cname_target = MagicMock()
    cname_target.target = MagicMock()
    cname_target.target.__str__ = lambda self: "loop.example.com."
    resolver.resolve.return_value = [cname_target]
    result = _follow_cname(resolver, "start.example.com", depth=11)
    assert result is None


def test_follow_cname_exception_returns_name():
    resolver = MagicMock()
    resolver.resolve.side_effect = Exception("NXDOMAIN")
    result = _follow_cname(resolver, "example.com")
    assert result == "example.com"


def test_scan_subdomains_with_takeover_detected():
    session = MagicMock()
    s = SubdomainTakeoverScanner(session)
    fake_resolver = MagicMock()

    resp = MagicMock()
    resp.text = "There isn't a GitHub Pages site here."

    def fake_get(url, **kwargs):
        return resp

    s.http.get = fake_get

    with patch("tblue.scanner.subdomain_takeover._import_dns", return_value=fake_resolver):
        with patch("tblue.scanner.subdomain_takeover._follow_cname",
                   return_value="user.github.io"):
            results = s.scan_subdomains(["abandoned.example.com"], "https://example.com")

    fails = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert fails
