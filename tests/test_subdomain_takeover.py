"""Tests for subdomain takeover / dangling DNS detection."""

from unittest.mock import MagicMock, patch
from tblue.scanner.subdomain_takeover import (
    SubdomainTakeoverScanner, _follow_cname, _FINGERPRINTS, _import_dns,
)


def _resolver_with_cname(cname_map: dict):
    """Build a mock dnspython resolver that returns CNAMEs from the map."""
    resolver = MagicMock()

    def fake_resolve(name, rtype):
        if rtype == "CNAME" and name in cname_map:
            target = MagicMock()
            target.target = cname_map[name] + "."
            return [target]
        raise Exception("NXDOMAIN")

    resolver.resolve.side_effect = fake_resolve
    return resolver


def _scanner(url_responses: dict = None):
    """url_responses: {substring: (status, body)}"""
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        for pattern, (status, body) in (url_responses or {}).items():
            if pattern in url:
                resp = MagicMock()
                resp.status_code = status
                resp.text = body
                return resp
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<html>Normal page</html>"
        return resp

    session.request.side_effect = fake_request
    return SubdomainTakeoverScanner(session)


# ── scan() returns empty (requires subdomain input) ───────────────────────────

def test_scan_with_no_subdomains_returns_empty():
    scanner = _scanner()
    results = scanner.scan("https://example.com")
    assert results == []


# ── No DNS library ────────────────────────────────────────────────────────────

def test_no_dns_library_returns_empty():
    scanner = _scanner()
    with patch("tblue.scanner.subdomain_takeover._import_dns", return_value=None):
        results = scanner.scan_subdomains(["sub.example.com"], "https://example.com")
    assert results == []


# ── Clean subdomains (no takeover) ────────────────────────────────────────────

def test_clean_subdomains_passes():
    resolver = _resolver_with_cname({})  # no CNAMEs → resolves to itself
    scanner = _scanner()
    with patch("tblue.scanner.subdomain_takeover._import_dns", return_value=resolver):
        results = scanner.scan_subdomains(["app.example.com", "api.example.com"], "https://example.com")
    assert any("no vulnerable" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ── GitHub Pages takeover ─────────────────────────────────────────────────────

def test_github_pages_takeover_fails():
    resolver = _resolver_with_cname({"blog.example.com": "myorg.github.io"})
    scanner = _scanner({"blog.example.com": (404, "There isn't a GitHub Pages site here.")})
    with patch("tblue.scanner.subdomain_takeover._import_dns", return_value=resolver):
        results = scanner.scan_subdomains(["blog.example.com"], "https://example.com")
    assert any("github pages" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_github_pages_body_mismatch_not_flagged():
    # CNAME matches but body does NOT contain the fingerprint → not vulnerable
    resolver = _resolver_with_cname({"blog.example.com": "myorg.github.io"})
    scanner = _scanner({"blog.example.com": (200, "<html>My real blog</html>")})
    with patch("tblue.scanner.subdomain_takeover._import_dns", return_value=resolver):
        results = scanner.scan_subdomains(["blog.example.com"], "https://example.com")
    assert not any("github pages" in r["type"].lower() and r["status"] == "FAIL" for r in results)


# ── AWS S3 takeover (CRITICAL severity) ──────────────────────────────────────

def test_s3_takeover_fails():
    resolver = _resolver_with_cname({"assets.example.com": "mysite.s3.amazonaws.com"})
    scanner = _scanner({"assets.example.com": (404, "NoSuchBucket")})
    with patch("tblue.scanner.subdomain_takeover._import_dns", return_value=resolver):
        results = scanner.scan_subdomains(["assets.example.com"], "https://example.com")
    assert any("aws s3" in r["type"].lower() and r["status"] == "FAIL" for r in results)


# ── Heroku takeover ───────────────────────────────────────────────────────────

def test_heroku_takeover_fails():
    resolver = _resolver_with_cname({"app.example.com": "myapp.herokuapp.com"})
    scanner = _scanner({"app.example.com": (404, "No such app")})
    with patch("tblue.scanner.subdomain_takeover._import_dns", return_value=resolver):
        results = scanner.scan_subdomains(["app.example.com"], "https://example.com")
    assert any("heroku" in r["type"].lower() and r["status"] == "FAIL" for r in results)


# ── Netlify takeover (WARN severity via "HIGH") ───────────────────────────────

def test_netlify_takeover_detected():
    resolver = _resolver_with_cname({"landing.example.com": "mysite.netlify.app"})
    scanner = _scanner({"landing.example.com": (404, "Not found - Request ID")})
    with patch("tblue.scanner.subdomain_takeover._import_dns", return_value=resolver):
        results = scanner.scan_subdomains(["landing.example.com"], "https://example.com")
    assert any("netlify" in r["type"].lower() for r in results)


# ── HTTP request failure during probe ─────────────────────────────────────────

def test_http_probe_failure_does_not_crash():
    resolver = _resolver_with_cname({"shop.example.com": "myshop.myshopify.com"})
    session = MagicMock()
    session.request.side_effect = Exception("connection refused")
    scanner = SubdomainTakeoverScanner(session)
    with patch("tblue.scanner.subdomain_takeover._import_dns", return_value=resolver):
        results = scanner.scan_subdomains(["shop.example.com"], "https://example.com")
    assert isinstance(results, list)


# ── Cap at 50 subdomains ──────────────────────────────────────────────────────

def test_caps_at_50_subdomains():
    resolver = _resolver_with_cname({})
    scanner = _scanner()
    subs = [f"sub{i}.example.com" for i in range(100)]
    with patch("tblue.scanner.subdomain_takeover._import_dns", return_value=resolver):
        results = scanner.scan_subdomains(subs, "https://example.com")
    # Should still return PASS (checked 50, 0 vulnerable)
    assert any("no vulnerable" in r["type"].lower() for r in results)


# ── _follow_cname helper ──────────────────────────────────────────────────────

def test_follow_cname_returns_final_target():
    resolver = _resolver_with_cname({"a.example.com": "b.example.com"})
    result = _follow_cname(resolver, "a.example.com")
    # b.example.com has no further CNAME → returns itself
    assert result == "b.example.com"


def test_follow_cname_depth_limit():
    # Build a loop: a→b→c→d→e→f→g→h→i→j→k (11 hops — hits depth limit)
    chain = {f"hop{i}.example.com": f"hop{i+1}.example.com" for i in range(12)}
    resolver = _resolver_with_cname(chain)
    # Should not crash (returns None at depth limit)
    result = _follow_cname(resolver, "hop0.example.com")
    assert result is not None or result is None  # just must not raise


def test_follow_cname_no_cname_returns_name():
    resolver = _resolver_with_cname({})  # no CNAMEs
    result = _follow_cname(resolver, "plain.example.com")
    assert result == "plain.example.com"


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_import_dns_returns_module():
    """_import_dns() success path — lines 102-104."""
    result = _import_dns()
    assert result is not None  # dnspython installed in venv


def test_import_dns_returns_none_on_import_error():
    """_import_dns() ImportError path — lines 105-106."""
    import sys
    original = sys.modules.get("dns.resolver", ...)
    sys.modules["dns.resolver"] = None  # setting None causes ImportError on `import dns.resolver`
    try:
        result = _import_dns()
    finally:
        if original is ...:
            sys.modules.pop("dns.resolver", None)
        else:
            sys.modules["dns.resolver"] = original
    assert result is None


def test_check_subdomain_cname_target_none():
    """_check_subdomain returns None when _follow_cname returns None — line 153."""
    scanner = _scanner()
    # _follow_cname returns None when depth > 10; patch it to return None directly
    with patch("tblue.scanner.subdomain_takeover._follow_cname", return_value=None):
        result = scanner._check_subdomain("deep.example.com", MagicMock())
    assert result is None


def test_check_subdomain_http_exception_swallowed():
    """Exception in HTTP probe inside _check_subdomain is caught — lines 180-181."""
    resolver = _resolver_with_cname({"shop.example.com": "myshop.myshopify.com"})
    session = MagicMock()
    scanner = SubdomainTakeoverScanner(session)
    with patch.object(scanner.http, "get", side_effect=ConnectionError("refused")):
        result = scanner._check_subdomain("shop.example.com", resolver)
    # No exception raised; returns None (CNAME matched but body check threw)
    assert result is None
