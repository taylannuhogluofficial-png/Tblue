"""Extra branch coverage for tblue.scanner.typosquatting."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.typosquatting import (
    _import_dns, _has_mx, _resolves, TyposquattingScanner
)


def test_import_dns_returns_module_or_none():
    # _import_dns() returns the dns.resolver module if dnspython is installed,
    # or None if it is not. Either outcome is valid — just ensure no exception.
    result = _import_dns()
    assert result is None or hasattr(result, "resolve")


def test_has_mx_returns_false_on_exception():
    resolver = MagicMock()
    resolver.resolve.side_effect = Exception("NXDOMAIN")
    assert _has_mx(resolver, "evil-nxdomain-typo.com") is False


def test_resolves_returns_false_on_exception():
    resolver = MagicMock()
    resolver.resolve.side_effect = Exception("Timeout")
    assert _resolves(resolver, "evil-nxdomain-typo.com") is False


def test_has_mx_returns_true_on_success():
    resolver = MagicMock()
    resolver.resolve.return_value = ["mx.example.com"]
    assert _has_mx(resolver, "example.com") is True


def test_resolves_returns_true_on_success():
    resolver = MagicMock()
    resolver.resolve.return_value = ["1.2.3.4"]
    assert _resolves(resolver, "example.com") is True


def test_scan_skips_dns_when_not_installed():
    session = MagicMock()
    s = TyposquattingScanner(session)
    with patch("tblue.scanner.typosquatting._import_dns", return_value=None):
        results = s.scan("https://example.com")
    assert results == []


def test_scan_skips_empty_domain():
    session = MagicMock()
    s = TyposquattingScanner(session)
    fake_resolver = MagicMock()
    with patch("tblue.scanner.typosquatting._import_dns", return_value=fake_resolver):
        # URL with no parseable host
        results = s.scan("https://")
    assert results == []


def test_scan_skips_domain_without_tld():
    session = MagicMock()
    s = TyposquattingScanner(session)
    fake_resolver = MagicMock()
    fake_resolver.resolve.side_effect = Exception("nxdomain")
    with patch("tblue.scanner.typosquatting._import_dns", return_value=fake_resolver):
        # "localhost" has no TLD — split returns ("localhost", "")
        results = s.scan("http://localhost")
    assert results == []


def test_scan_with_mx_records_fails():
    session = MagicMock()
    s = TyposquattingScanner(session)
    fake_resolver = MagicMock()

    def resolve_side_effect(domain, rtype):
        if rtype == "A":
            return ["1.2.3.4"]
        if rtype == "MX":
            return ["mail.attacker.com"]
        raise Exception("unknown")

    fake_resolver.resolve.side_effect = resolve_side_effect
    with patch("tblue.scanner.typosquatting._import_dns", return_value=fake_resolver):
        with patch("tblue.scanner.typosquatting._generate_variants",
                   return_value={"examp1e.com"}):
            results = s.scan("https://example.com")

    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("mail" in r["type"].lower() or "mx" in r["type"].lower() for r in fails)


def test_scan_registered_but_no_mx_warns():
    session = MagicMock()
    s = TyposquattingScanner(session)
    fake_resolver = MagicMock()

    def resolve_side_effect(domain, rtype):
        if rtype == "A":
            return ["1.2.3.4"]
        raise Exception("no MX")

    fake_resolver.resolve.side_effect = resolve_side_effect
    with patch("tblue.scanner.typosquatting._import_dns", return_value=fake_resolver):
        with patch("tblue.scanner.typosquatting._generate_variants",
                   return_value={"examp1e.com"}):
            results = s.scan("https://example.com")

    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert warns_or_fails
