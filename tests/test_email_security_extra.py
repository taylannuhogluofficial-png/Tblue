"""Extra branch coverage for tblue.scanner.email_security."""

from unittest.mock import MagicMock, patch
from tblue.scanner.email_security import EmailSecurityScanner

URL = "https://example.com"


def _scanner():
    session = MagicMock()
    return EmailSecurityScanner(session)


def test_dns_unavailable_returns_empty():
    """Branch: _DNS_AVAILABLE is False — returns empty list immediately."""
    s = _scanner()
    with patch("tblue.scanner.email_security._DNS_AVAILABLE", False):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert results == []


def test_no_domain_in_url_returns_empty():
    """Branch: URL with empty netloc — domain empty, returns early."""
    s = _scanner()
    with patch("tblue.scanner.email_security._DNS_AVAILABLE", True):
        with patch("tblue.scanner.email_security._txt_records", return_value=[]):
            with patch("tblue.scanner.email_security._caa_records", return_value=[]):
                results = s.scan("https://")
    assert isinstance(results, list)
    assert results == []


def test_spf_record_missing_fails():
    """Branch: no SPF TXT record for domain — FAIL."""
    s = _scanner()

    def txt_side_effect(name):
        return []  # no records

    with patch("tblue.scanner.email_security._DNS_AVAILABLE", True):
        with patch("tblue.scanner.email_security._txt_records",
                   side_effect=txt_side_effect):
            with patch("tblue.scanner.email_security._caa_records", return_value=[]):
                results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("spf" in r["type"].lower() for r in fails)


def test_dmarc_record_missing_fails():
    """Branch: SPF present but no DMARC record — FAIL."""
    s = _scanner()

    def txt_side_effect(name):
        if "_dmarc" in name:
            return []
        return ["v=spf1 -all"]

    with patch("tblue.scanner.email_security._DNS_AVAILABLE", True):
        with patch("tblue.scanner.email_security._txt_records",
                   side_effect=txt_side_effect):
            with patch("tblue.scanner.email_security._caa_records", return_value=[]):
                results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("dmarc" in r["type"].lower() for r in fails)


def test_dmarc_p_none_warns():
    """Branch: DMARC record with p=none — WARN (no enforcement)."""
    s = _scanner()

    def txt_side_effect(name):
        if "_dmarc" in name:
            return ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"]
        return ["v=spf1 -all"]

    with patch("tblue.scanner.email_security._DNS_AVAILABLE", True):
        with patch("tblue.scanner.email_security._txt_records",
                   side_effect=txt_side_effect):
            with patch("tblue.scanner.email_security._caa_records", return_value=[]):
                results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad
    assert any("dmarc" in r["type"].lower() and "none" in r["type"].lower()
               for r in bad)


def test_caa_records_missing_warns():
    """Branch: no CAA records for domain — WARN."""
    s = _scanner()

    def txt_side_effect(name):
        if "_dmarc" in name:
            return ["v=DMARC1; p=reject"]
        return ["v=spf1 -all"]

    with patch("tblue.scanner.email_security._DNS_AVAILABLE", True):
        with patch("tblue.scanner.email_security._txt_records",
                   side_effect=txt_side_effect):
            with patch("tblue.scanner.email_security._caa_records", return_value=[]):
                results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("caa" in r["type"].lower() for r in warns)
