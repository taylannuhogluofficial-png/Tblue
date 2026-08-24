"""Tests for advanced DNS security checks (CAA, DNSSEC, NS diversity)."""

from unittest.mock import MagicMock
from tblue.scanner.dns_advanced import DNSAdvancedScanner


def _resolver_with(records: dict):
    resolver = MagicMock()

    def fake_resolve(name, rdtype):
        key = (name.lower(), rdtype.upper())
        if key in records:
            return records[key]
        raise Exception(f"NXDOMAIN: {name} {rdtype}")

    resolver.resolve.side_effect = fake_resolve
    return resolver


def _scanner(resolver):
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = 200
    session.request.return_value = resp
    scanner = DNSAdvancedScanner(session)
    return scanner


def _run(resolver, url="https://example.com"):
    import tblue.scanner.dns_advanced as mod
    original = mod._import_dns
    mod._import_dns = lambda: (resolver, MagicMock())
    try:
        scanner = _scanner(resolver)
        return scanner.scan(url)
    finally:
        mod._import_dns = original


# ── CAA ───────────────────────────────────────────────────────────────────────

def test_caa_missing_warns():
    resolver = _resolver_with({})
    results = _run(resolver)
    assert any("no caa record" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_caa_configured_passes():
    rdata = MagicMock()
    rdata.tag = "issue"
    rdata.value = '"letsencrypt.org"'
    resolver = _resolver_with({("example.com", "CAA"): [rdata]})
    results = _run(resolver)
    assert any("caa record configured" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_caa_allows_any_warns():
    rdata = MagicMock()
    rdata.tag = "issue"
    rdata.value = '""'  # empty = any CA
    resolver = _resolver_with({("example.com", "CAA"): [rdata]})
    results = _run(resolver)
    assert any("allows any ca" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── DNSSEC ────────────────────────────────────────────────────────────────────

def test_dnssec_enabled_passes():
    ds_rdata = MagicMock()
    resolver = _resolver_with({("example.com", "DS"): [ds_rdata]})
    results = _run(resolver)
    assert any("dnssec enabled" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_dnssec_not_configured_warns():
    resolver = _resolver_with({})  # No DS, no DNSKEY
    results = _run(resolver)
    assert any("dnssec not enabled" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_dnssec_partial_dnskey_only_warns():
    dnskey = MagicMock()
    resolver = _resolver_with({("example.com", "DNSKEY"): [dnskey]})
    results = _run(resolver)
    assert any("partially configured" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── NS diversity ──────────────────────────────────────────────────────────────

def _ns(name):
    rdata = MagicMock()
    rdata.target = MagicMock()
    rdata.target.__str__ = lambda self: name + "."
    return rdata


def test_ns_diverse_passes():
    resolver = _resolver_with({
        ("example.com", "NS"): [_ns("ns1.cloudflare.com"), _ns("ns2.route53.net")],
    })
    results = _run(resolver)
    assert any("nameservers are diverse" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_ns_same_provider_warns():
    resolver = _resolver_with({
        ("example.com", "NS"): [_ns("ns1.cloudflare.com"), _ns("ns2.cloudflare.com")],
    })
    results = _run(resolver)
    assert any("same provider" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_ns_single_warns():
    resolver = _resolver_with({
        ("example.com", "NS"): [_ns("ns1.cloudflare.com")],
    })
    results = _run(resolver)
    assert any("single nameserver" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_no_dnspython_returns_empty():
    import tblue.scanner.dns_advanced as mod
    original = mod._import_dns
    mod._import_dns = lambda: (None, None)
    try:
        session = MagicMock()
        scanner = DNSAdvancedScanner(session)
        results = scanner.scan("https://example.com")
        assert results == []
    finally:
        mod._import_dns = original


def test_empty_host_returns_early():
    """URL with no hostname triggers early return on line 54."""
    import tblue.scanner.dns_advanced as mod
    resolver = MagicMock()
    original = mod._import_dns
    mod._import_dns = lambda: (resolver, MagicMock())
    try:
        session = MagicMock()
        scanner = DNSAdvancedScanner(session)
        results = scanner.scan("http://")  # no hostname
        assert results == []
    finally:
        mod._import_dns = original


def test_caa_rdata_attribute_error_skipped():
    """rdata.tag attribute raising Exception skips gracefully (lines 74-75)."""
    rdata = MagicMock()

    def bad_tag():
        raise AttributeError("no tag")

    rdata.tag = property(bad_tag)

    # Make rdata.tag raise when accessed as attribute
    type(rdata).tag = property(lambda self: (_ for _ in ()).throw(AttributeError("no tag")))

    resolver = _resolver_with({("example.com", "CAA"): [rdata]})
    results = _run(resolver)
    # Should not crash — either WARN or PASS depending on whether issuers list is empty
    assert isinstance(results, list)


def test_import_dns_function_importerror():
    """_import_dns returns (None, None) when dns is unavailable (lines 26-31)."""
    import sys
    from unittest.mock import patch
    import tblue.scanner.dns_advanced as mod
    # Setting a module key to None in sys.modules makes Python raise ImportError
    # without evicting the real module objects (safe on Python 3.14).
    with patch.dict(sys.modules, {"dns": None, "dns.resolver": None, "dns.exception": None}):
        r, e = mod._import_dns()
    assert r is None
    assert e is None
