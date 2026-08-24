"""Extra coverage for dns_advanced — lines 28-29 (_import_dns ImportError), 74-75 (CAA rdata exception)."""

import sys
import importlib.abc
import importlib.machinery
from unittest.mock import MagicMock, patch
from tblue.scanner.dns_advanced import DNSAdvancedScanner, _import_dns

URL = "https://example.com"


def _make_scanner():
    return DNSAdvancedScanner(MagicMock())


# ── _import_dns ImportError path (lines 28-29) ───────────────────────────────

class _DnsBlocker(importlib.abc.MetaPathFinder):
    """MetaPathFinder that raises ImportError for any dns.* module."""
    def find_spec(self, fullname, path, target=None):
        if fullname == "dns" or fullname.startswith("dns."):
            raise ImportError(f"blocked for test: {fullname}")
        return None


def test_import_dns_returns_none_when_dnspython_absent():
    """_import_dns returns (None, None) on ImportError via MetaPathFinder (lines 28-29)."""
    # Remove cached dns modules so the import machinery actually runs
    dns_backup = {k: v for k, v in sys.modules.items() if k.startswith("dns")}
    for k in list(dns_backup):
        del sys.modules[k]

    blocker = _DnsBlocker()
    sys.meta_path.insert(0, blocker)
    try:
        resolver, exc = _import_dns()
    finally:
        sys.meta_path.remove(blocker)
        sys.modules.update(dns_backup)

    assert resolver is None
    assert exc is None


def test_import_dns_success_path():
    """Real _import_dns() with dnspython installed covers lines 28-29 (success path)."""
    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        import pytest
        pytest.skip("dnspython not installed")

    resolver, exc = _import_dns()
    assert resolver is not None
    assert exc is not None


def test_scanner_returns_empty_when_dns_unavailable():
    """DNSAdvancedScanner returns empty list when dnspython is not installed."""
    s = _make_scanner()
    with patch("tblue.scanner.dns_advanced._import_dns", return_value=(None, None)):
        results = s.scan(URL)
    assert results == []


# ── CAA record restricts issuers (lines 74-75) ───────────────────────────────

def test_caa_record_with_specific_issuer_passes():
    """CAA record restricting issuers to a CA produces PASS (lines 74-75)."""
    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        import pytest
        pytest.skip("dnspython not installed")

    # Build a minimal mock CAA rdata
    mock_caa = MagicMock()
    mock_caa.tag = "issue"
    mock_caa.value = '"letsencrypt.org"'

    mock_answers = [mock_caa]

    def mock_resolve(name, rdtype):
        if rdtype == "CAA":
            return mock_answers
        raise dns.resolver.NoAnswer

    s = _make_scanner()
    with patch("tblue.scanner.dns_advanced._import_dns",
               return_value=(dns.resolver, dns.exception)):
        with patch.object(dns.resolver, "resolve", side_effect=mock_resolve):
            results = s.scan(URL)

    caa_results = [r for r in results if "caa" in r["type"].lower()]
    assert any(r["status"] == "PASS" for r in caa_results), \
        f"Expected PASS for CAA restricting to letsencrypt.org: {caa_results}"


# ── CAA rdata attribute access raises — except Exception pass (lines 74-75) ──

def test_caa_rdata_exception_is_caught():
    """CAA rdata that raises on attribute access → except Exception: pass (lines 74-75)."""
    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        import pytest
        pytest.skip("dnspython not installed")

    class _BadRdata:
        """rdata whose .tag property raises a non-AttributeError exception."""
        @property
        def tag(self):
            raise TypeError("incompatible rdata type")

        value = '"letsencrypt.org"'

    mock_answers = [_BadRdata()]

    def mock_resolve(name, rdtype):
        if rdtype == "CAA":
            return mock_answers
        raise dns.resolver.NoAnswer

    s = _make_scanner()
    with patch("tblue.scanner.dns_advanced._import_dns",
               return_value=(dns.resolver, dns.exception)):
        with patch.object(dns.resolver, "resolve", side_effect=mock_resolve):
            results = s.scan(URL)

    # Exception in rdata processing is caught → scan continues
    assert isinstance(results, list)
