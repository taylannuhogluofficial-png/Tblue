"""Tests for DNSSEC and subdomain surface scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.dns_security import DNSSecurityScanner, _extract_domain


def make_scanner():
    return DNSSecurityScanner(MagicMock())


# ── _extract_domain ───────────────────────────────────────────────────────────

def test_extract_domain_strips_scheme():
    assert _extract_domain("https://example.com/path") == "example.com"


def test_extract_domain_strips_www():
    assert _extract_domain("https://www.example.com") == "example.com"


def test_extract_domain_handles_no_scheme():
    assert _extract_domain("example.com") == "example.com"


def test_extract_domain_empty_returns_empty():
    assert _extract_domain("") == ""


# ── DNSSEC ────────────────────────────────────────────────────────────────────

def test_dnssec_configured_passes(monkeypatch):
    import dns.resolver
    import dns.exception

    mock_answer = MagicMock()
    mock_answer.__bool__ = lambda self: True

    monkeypatch.setattr(
        "tblue.scanner.dns_security._import_dns",
        lambda: (dns.resolver, dns.exception)
    )
    monkeypatch.setattr(dns.resolver, "resolve",
                        lambda name, rdtype: mock_answer if rdtype == "DNSKEY" else [])

    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("dnssec" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_dnssec_missing_warns(monkeypatch):
    import dns.resolver
    import dns.exception

    def raise_no_answer(name, rdtype):
        raise Exception("NoAnswer: no DNSKEY records")

    monkeypatch.setattr(
        "tblue.scanner.dns_security._import_dns",
        lambda: (dns.resolver, dns.exception)
    )
    monkeypatch.setattr(dns.resolver, "resolve", raise_no_answer)

    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("dnssec" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── Subdomain surface ─────────────────────────────────────────────────────────

def test_subdomains_found_reported(monkeypatch):
    import dns.resolver
    import dns.exception

    def fake_resolve(name, rdtype):
        if rdtype == "DNSKEY":
            raise Exception("NoAnswer")
        if rdtype == "A" and name.startswith("api."):
            answer = MagicMock()
            answer.address = "1.2.3.4"
            return [answer]
        raise Exception("NXDOMAIN")

    monkeypatch.setattr(
        "tblue.scanner.dns_security._import_dns",
        lambda: (dns.resolver, dns.exception)
    )
    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)

    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("subdomain" in r["type"].lower() for r in results)


def test_no_subdomains_passes(monkeypatch):
    import dns.resolver
    import dns.exception

    def always_nxdomain(name, rdtype):
        raise Exception("NXDOMAIN")

    monkeypatch.setattr(
        "tblue.scanner.dns_security._import_dns",
        lambda: (dns.resolver, dns.exception)
    )
    monkeypatch.setattr(dns.resolver, "resolve", always_nxdomain)

    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    subdomain_results = [r for r in results if "subdomain" in r["type"].lower()]
    assert any(r["status"] == "PASS" for r in subdomain_results)


def test_no_dnspython_returns_empty(monkeypatch):
    monkeypatch.setattr(
        "tblue.scanner.dns_security._import_dns",
        lambda: (None, None)
    )
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert results == []


# ── _import_dns and _nxdomain_exc direct calls ────────────────────────────────

def test_import_dns_returns_modules():
    from tblue.scanner.dns_security import _import_dns
    resolver, exception = _import_dns()
    # dnspython is installed — both should be non-None
    assert resolver is not None
    assert exception is not None


def test_nxdomain_exc_returns_exception():
    from tblue.scanner.dns_security import _nxdomain_exc
    exc = _nxdomain_exc()
    assert exc is not None


# ── Empty domain returns early ─────────────────────────────────────────────────

def test_empty_url_returns_empty(monkeypatch):
    import dns.resolver
    import dns.exception
    monkeypatch.setattr(
        "tblue.scanner.dns_security._import_dns",
        lambda: (dns.resolver, dns.exception)
    )
    scanner = make_scanner()
    # URL that results in empty domain
    results = scanner.scan("")
    assert results == []


# ── Falsy answers from DNSSEC resolver ─────────────────────────────────────────

def test_dnssec_empty_answers_silently_passes(monkeypatch):
    import dns.resolver
    import dns.exception

    def fake_resolve(name, rdtype):
        if rdtype == "DNSKEY":
            return []  # falsy — if answers: is False
        raise Exception("NXDOMAIN")

    monkeypatch.setattr(
        "tblue.scanner.dns_security._import_dns",
        lambda: (dns.resolver, dns.exception)
    )
    monkeypatch.setattr(dns.resolver, "resolve", fake_resolve)
    scanner = make_scanner()
    # Should not crash, does not add DNSSEC PASS or WARN
    results = scanner.scan("https://example.com")
    dnssec_results = [r for r in results if "dnssec" in r["type"].lower()]
    assert len(dnssec_results) == 0
