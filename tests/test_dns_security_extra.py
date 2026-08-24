"""Extra coverage for dns_security — lines 39-40 (ImportError), 47-48 (nxdomain exc), 153-154 (extract_domain exc)."""

import sys
from unittest.mock import MagicMock, patch
from tblue.scanner.dns_security import (
    DNSSecurityScanner, _import_dns, _extract_domain, _nxdomain_exc,
)

URL = "https://example.com"


def _make_scanner():
    return DNSSecurityScanner(MagicMock())


# ── _import_dns ImportError path (lines 39-40) ───────────────────────────────

def test_import_dns_returns_none_tuple_when_dnspython_absent():
    """_import_dns returns (None, None) when dnspython is not installed (lines 39-40)."""
    # Temporarily mask dns.resolver in sys.modules to simulate ImportError
    saved = {k: v for k, v in sys.modules.items() if k.startswith("dns")}
    try:
        # Set dns modules to None → makes 'import dns.resolver' raise ImportError
        sys.modules["dns"] = None
        sys.modules["dns.resolver"] = None
        sys.modules["dns.exception"] = None
        resolver, exc = _import_dns()
        assert resolver is None
        assert exc is None
    finally:
        # Restore
        for k in list(sys.modules.keys()):
            if k.startswith("dns") and sys.modules[k] is None:
                del sys.modules[k]
        sys.modules.update(saved)


# ── _nxdomain_exc exception path (lines 47-48) ───────────────────────────────

def test_nxdomain_exc_returns_base_exception_when_dns_absent():
    """_nxdomain_exc returns Exception class when dns is unavailable (lines 47-48)."""
    saved = {k: v for k, v in sys.modules.items() if k.startswith("dns")}
    try:
        sys.modules["dns"] = None
        sys.modules["dns.resolver"] = None
        result = _nxdomain_exc()
        assert result is Exception
    finally:
        for k in list(sys.modules.keys()):
            if k.startswith("dns") and sys.modules[k] is None:
                del sys.modules[k]
        sys.modules.update(saved)


# ── _extract_domain exception path (lines 153-154) ───────────────────────────

def test_extract_domain_exception_returns_empty_string():
    """Exception inside _extract_domain (urlparse failure) returns '' (lines 153-154)."""
    with patch("tblue.scanner.dns_security.urlparse", side_effect=Exception("parse error")):
        result = _extract_domain("https://example.com")
    assert result == ""


# ── dns_resolver is None → scanner returns early ─────────────────────────────

def test_scanner_returns_empty_when_dnspython_not_installed():
    """DNSSecurityScanner returns empty list when dns is unavailable (line 61-62)."""
    s = _make_scanner()
    with patch("tblue.scanner.dns_security._import_dns", return_value=(None, None)):
        results = s.scan(URL)
    assert results == []
