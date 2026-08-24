"""Tests for typosquatting / lookalike domain detector."""

from unittest.mock import MagicMock, patch
from tblue.scanner.typosquatting import (
    TyposquattingScanner, _generate_variants, _split_domain,
    _import_dns, _has_mx, _resolves,
)


def make_scanner():
    return TyposquattingScanner(MagicMock())


# ── Helpers ───────────────────────────────────────────────────────────────────

def test_split_domain():
    assert _split_domain("example.com") == ("example", "com")


def test_split_domain_no_tld():
    name, tld = _split_domain("localhost")
    assert name == "localhost"


def test_generate_variants_not_empty():
    variants = _generate_variants("example", "com")
    assert len(variants) > 10


def test_generate_variants_excludes_real_domain():
    variants = _generate_variants("example", "com")
    assert "example.com" not in variants


def test_generate_variants_includes_tld_swap():
    variants = _generate_variants("example", "com")
    assert "example.net" in variants or "example.io" in variants


def test_generate_variants_includes_char_omission():
    variants = _generate_variants("example", "com")
    assert "exampl.com" in variants or "xample.com" in variants


# ── Scanner ───────────────────────────────────────────────────────────────────

def test_no_typosquats_passes(monkeypatch):
    import dns.resolver
    monkeypatch.setattr(
        "tblue.scanner.typosquatting._import_dns",
        lambda: dns.resolver
    )
    monkeypatch.setattr(
        "tblue.scanner.typosquatting._resolves",
        lambda resolver, domain: False
    )
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("no registered" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_typosquat_with_mx_fails(monkeypatch):
    import dns.resolver
    monkeypatch.setattr(
        "tblue.scanner.typosquatting._import_dns",
        lambda: dns.resolver
    )
    call_count = {"n": 0}
    def fake_resolves(resolver, domain):
        call_count["n"] += 1
        return call_count["n"] <= 3  # first 3 variants "resolve"

    monkeypatch.setattr("tblue.scanner.typosquatting._resolves", fake_resolves)
    monkeypatch.setattr("tblue.scanner.typosquatting._has_mx", lambda r, d: True)

    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("mail server" in r["type"].lower() and r["status"] == "FAIL"
               for r in results)


def test_typosquat_registered_no_mx_warns(monkeypatch):
    import dns.resolver
    monkeypatch.setattr(
        "tblue.scanner.typosquatting._import_dns",
        lambda: dns.resolver
    )
    call_count = {"n": 0}
    def fake_resolves(resolver, domain):
        call_count["n"] += 1
        return call_count["n"] == 1

    monkeypatch.setattr("tblue.scanner.typosquatting._resolves", fake_resolves)
    monkeypatch.setattr("tblue.scanner.typosquatting._has_mx", lambda r, d: False)

    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("registered lookalike" in r["type"].lower() and r["status"] == "WARN"
               for r in results)


def test_no_dnspython_returns_empty(monkeypatch):
    monkeypatch.setattr("tblue.scanner.typosquatting._import_dns", lambda: None)
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert results == []


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_import_dns_returns_module():
    """_import_dns() success path — lines 43-45."""
    result = _import_dns()
    assert result is not None  # dnspython is installed in the test env


def test_import_dns_returns_none_on_import_error():
    """_import_dns() ImportError path — lines 46-47."""
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


def test_has_mx_returns_true_on_success():
    """_has_mx() try path — lines 51-53."""
    resolver = MagicMock()
    resolver.resolve.return_value = [MagicMock()]
    assert _has_mx(resolver, "example.com") is True


def test_has_mx_returns_false_on_exception():
    """_has_mx() except path — lines 54-55."""
    resolver = MagicMock()
    resolver.resolve.side_effect = Exception("NXDOMAIN")
    assert _has_mx(resolver, "nonexistent.invalid") is False


def test_resolves_returns_true_on_success():
    """_resolves() try path — lines 59-61."""
    resolver = MagicMock()
    resolver.resolve.return_value = [MagicMock()]
    assert _resolves(resolver, "example.com") is True


def test_resolves_returns_false_on_exception():
    """_resolves() except path — lines 62-63."""
    resolver = MagicMock()
    resolver.resolve.side_effect = Exception("NXDOMAIN")
    assert _resolves(resolver, "nonexistent.invalid") is False


def test_empty_hostname_returns_early(monkeypatch):
    """Return [] when URL has no hostname — line 137."""
    import dns.resolver
    monkeypatch.setattr("tblue.scanner.typosquatting._import_dns", lambda: dns.resolver)
    scanner = make_scanner()
    results = scanner.scan("https://")
    assert results == []


def test_no_tld_returns_early(monkeypatch):
    """Return [] when hostname has no TLD — line 141."""
    import dns.resolver
    monkeypatch.setattr("tblue.scanner.typosquatting._import_dns", lambda: dns.resolver)
    scanner = make_scanner()
    results = scanner.scan("https://localhost")
    assert results == []


def test_resolves_exception_in_loop_continues(monkeypatch):
    """Exception from _resolves inside variant loop is swallowed — lines 155-156."""
    import dns.resolver
    monkeypatch.setattr("tblue.scanner.typosquatting._import_dns", lambda: dns.resolver)

    call_count = {"n": 0}
    def raising_resolves(resolver, domain):
        call_count["n"] += 1
        if call_count["n"] <= 5:
            raise Exception("DNS timeout")
        return False

    monkeypatch.setattr("tblue.scanner.typosquatting._resolves", raising_resolves)
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    # No crash — exception is caught and loop continues
    assert isinstance(results, list)
