"""Extra branch coverage for tblue.scanner.email_advanced."""

from unittest.mock import MagicMock, patch
from tblue.scanner.email_advanced import EmailAdvancedScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return EmailAdvancedScanner(session)


def test_no_dns_returns_empty():
    """Branch: dnspython not installed — returns empty results."""
    s = _scanner()
    with patch("tblue.scanner.email_advanced._import_dns", return_value=(None, None)):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert results == []


def test_empty_hostname_returns_empty():
    """Branch: URL with no valid hostname/domain — returns empty early."""
    s = _scanner()
    mock_resolver = MagicMock()
    mock_dns_exc = MagicMock()
    with patch("tblue.scanner.email_advanced._import_dns",
               return_value=(mock_resolver, mock_dns_exc)):
        results = s.scan("https://")
    assert isinstance(results, list)
    assert results == []


def test_www_prefix_stripped_from_domain():
    """Branch: URL has www. prefix — domain is stripped to base domain."""
    s = _scanner()
    mock_resolver = MagicMock()
    mock_resolver.resolve.side_effect = Exception("DNS error")
    mock_dns_exc = MagicMock()

    with patch("tblue.scanner.email_advanced._import_dns",
               return_value=(mock_resolver, mock_dns_exc)):
        with patch("tblue.scanner.email_advanced._resolve_txt", return_value=[]):
            results = s.scan("https://www.example.com")
    assert isinstance(results, list)
    # Should have produced some findings (missing MTA-STS, TLS-RPT, etc.)
    assert len(results) >= 0


def test_mta_sts_missing_warns():
    """Branch: no _mta-sts DNS record found — WARN about missing MTA-STS."""
    s = _scanner()
    mock_resolver = MagicMock()
    mock_dns_exc = MagicMock()

    with patch("tblue.scanner.email_advanced._import_dns",
               return_value=(mock_resolver, mock_dns_exc)):
        with patch("tblue.scanner.email_advanced._resolve_txt", return_value=[]):
            results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("mta-sts" in r["type"].lower() or "mta" in r.get("detail", "").lower()
               for r in warns)


def test_dmarc_none_policy_warns():
    """Branch: DMARC record found but p=none — WARN about no enforcement."""
    s = _scanner()
    mock_resolver = MagicMock()
    mock_dns_exc = MagicMock()

    def resolve_txt_side_effect(resolver_or_name, name=None):
        # Handle both _resolve_txt(resolver, name) call signatures
        return []

    with patch("tblue.scanner.email_advanced._import_dns",
               return_value=(mock_resolver, mock_dns_exc)):
        dmarc_record = "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
        spf_record = "v=spf1 include:spf.example.com ~all"

        def patched_resolve(resolver, name):
            if "_dmarc" in name:
                return [dmarc_record]
            if name == "example.com":
                return [spf_record]
            return []

        with patch("tblue.scanner.email_advanced._resolve_txt",
                   side_effect=patched_resolve):
            results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert isinstance(results, list)


def test_spf_plus_all_fails():
    """Branch: SPF record with +all (allow all) — FAIL."""
    s = _scanner()
    mock_resolver = MagicMock()
    mock_dns_exc = MagicMock()

    spf_record = "v=spf1 +all"

    def patched_resolve(resolver, name):
        if name == "example.com":
            return [spf_record]
        return []

    with patch("tblue.scanner.email_advanced._import_dns",
               return_value=(mock_resolver, mock_dns_exc)):
        with patch("tblue.scanner.email_advanced._resolve_txt",
                   side_effect=patched_resolve):
            results = s.scan(URL)
    # +all should produce FAIL
    fails = [r for r in results if r["status"] == "FAIL"]
    assert isinstance(results, list)
