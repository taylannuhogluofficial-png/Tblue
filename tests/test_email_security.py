"""
Tests for email security scanner (SPF / DKIM / DMARC / CAA).
Uses monkeypatching to avoid real DNS queries.
"""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.email_security import EmailSecurityScanner, _txt_records, _caa_records


def make_scanner():
    session = MagicMock()
    return EmailSecurityScanner(session)


# ── SPF tests ─────────────────────────────────────────────────────────────────

def test_spf_strict_passes(monkeypatch):
    def fake_txt(name):
        if name == "example.com":
            return ["v=spf1 include:_spf.google.com -all"]
        return []
    monkeypatch.setattr("tblue.scanner.email_security._txt_records", fake_txt)
    monkeypatch.setattr("tblue.scanner.email_security._caa_records", lambda n: ["0 issue \"letsencrypt.org\""])

    s = make_scanner()
    results = s.scan("https://example.com")
    spf = [r for r in results if "SPF" in r["type"]]
    assert any(r["status"] == "PASS" for r in spf)


def test_spf_soft_fail_warns(monkeypatch):
    def fake_txt(name):
        if name == "example.com":
            return ["v=spf1 include:_spf.google.com ~all"]
        return []
    monkeypatch.setattr("tblue.scanner.email_security._txt_records", fake_txt)
    monkeypatch.setattr("tblue.scanner.email_security._caa_records", lambda n: [])

    s = make_scanner()
    results = s.scan("https://example.com")
    spf = [r for r in results if "SPF" in r["type"] and "~all" in r["type"]]
    assert any(r["status"] == "WARN" for r in spf)


def test_spf_missing_fails(monkeypatch):
    monkeypatch.setattr("tblue.scanner.email_security._txt_records", lambda n: [])
    monkeypatch.setattr("tblue.scanner.email_security._caa_records", lambda n: [])

    s = make_scanner()
    results = s.scan("https://example.com")
    spf = [r for r in results if "SPF" in r["type"] and r["status"] == "FAIL"]
    assert len(spf) > 0


def test_spf_permissive_fails(monkeypatch):
    def fake_txt(name):
        if name == "example.com":
            return ["v=spf1 include:_spf.google.com +all"]
        return []
    monkeypatch.setattr("tblue.scanner.email_security._txt_records", fake_txt)
    monkeypatch.setattr("tblue.scanner.email_security._caa_records", lambda n: [])

    s = make_scanner()
    results = s.scan("https://example.com")
    assert any("permissive" in r["type"].lower() and r["status"] == "FAIL" for r in results)


# ── DMARC tests ───────────────────────────────────────────────────────────────

def test_dmarc_reject_passes(monkeypatch):
    def fake_txt(name):
        if "example.com" in name and name.startswith("_dmarc"):
            return ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
        return []
    monkeypatch.setattr("tblue.scanner.email_security._txt_records", fake_txt)
    monkeypatch.setattr("tblue.scanner.email_security._caa_records", lambda n: [])

    s = make_scanner()
    results = s.scan("https://example.com")
    dmarc = [r for r in results if "DMARC" in r["type"]]
    assert any(r["status"] == "PASS" for r in dmarc)


def test_dmarc_none_fails(monkeypatch):
    def fake_txt(name):
        if "example.com" in name and name.startswith("_dmarc"):
            return ["v=DMARC1; p=none"]
        return []
    monkeypatch.setattr("tblue.scanner.email_security._txt_records", fake_txt)
    monkeypatch.setattr("tblue.scanner.email_security._caa_records", lambda n: [])

    s = make_scanner()
    results = s.scan("https://example.com")
    dmarc_fails = [r for r in results if "DMARC" in r["type"] and r["status"] == "FAIL"]
    assert len(dmarc_fails) > 0


def test_dmarc_missing_fails(monkeypatch):
    monkeypatch.setattr("tblue.scanner.email_security._txt_records", lambda n: [])
    monkeypatch.setattr("tblue.scanner.email_security._caa_records", lambda n: [])

    s = make_scanner()
    results = s.scan("https://example.com")
    dmarc_fails = [r for r in results if "DMARC" in r["type"] and r["status"] == "FAIL"]
    assert len(dmarc_fails) > 0


def test_dmarc_quarantine_warns(monkeypatch):
    def fake_txt(name):
        if name.startswith("_dmarc"):
            return ["v=DMARC1; p=quarantine; rua=mailto:x@example.com"]
        return []
    monkeypatch.setattr("tblue.scanner.email_security._txt_records", fake_txt)
    monkeypatch.setattr("tblue.scanner.email_security._caa_records", lambda n: [])

    s = make_scanner()
    results = s.scan("https://example.com")
    assert any("quarantine" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_dmarc_missing_rua_warns(monkeypatch):
    def fake_txt(name):
        if name.startswith("_dmarc"):
            return ["v=DMARC1; p=reject"]  # no rua
        return []
    monkeypatch.setattr("tblue.scanner.email_security._txt_records", fake_txt)
    monkeypatch.setattr("tblue.scanner.email_security._caa_records", lambda n: [])

    s = make_scanner()
    results = s.scan("https://example.com")
    assert any("reporting not configured" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── DKIM tests ────────────────────────────────────────────────────────────────

def test_dkim_found_passes(monkeypatch):
    def fake_txt(name):
        if "_domainkey.example.com" in name:
            return ["v=DKIM1; k=rsa; p=" + "A" * 400]  # long key = 2048+ bits
        if "example.com" == name:
            return ["v=spf1 -all"]
        return []
    monkeypatch.setattr("tblue.scanner.email_security._txt_records", fake_txt)
    monkeypatch.setattr("tblue.scanner.email_security._caa_records", lambda n: [])

    s = make_scanner()
    results = s.scan("https://example.com")
    dkim = [r for r in results if "DKIM" in r["type"]]
    assert any(r["status"] == "PASS" for r in dkim)


def test_dkim_not_found_warns(monkeypatch):
    monkeypatch.setattr("tblue.scanner.email_security._txt_records", lambda n: [])
    monkeypatch.setattr("tblue.scanner.email_security._caa_records", lambda n: [])

    s = make_scanner()
    results = s.scan("https://example.com")
    dkim_warns = [r for r in results if "DKIM" in r["type"] and r["status"] == "WARN"]
    assert len(dkim_warns) > 0


# ── CAA tests ─────────────────────────────────────────────────────────────────

def test_caa_present_passes(monkeypatch):
    monkeypatch.setattr("tblue.scanner.email_security._txt_records", lambda n: [])
    monkeypatch.setattr("tblue.scanner.email_security._caa_records",
                        lambda n: ['0 issue "letsencrypt.org"'])

    s = make_scanner()
    results = s.scan("https://example.com")
    caa = [r for r in results if "CAA" in r["type"]]
    assert any(r["status"] == "PASS" for r in caa)


def test_caa_missing_warns(monkeypatch):
    monkeypatch.setattr("tblue.scanner.email_security._txt_records", lambda n: [])
    monkeypatch.setattr("tblue.scanner.email_security._caa_records", lambda n: [])

    s = make_scanner()
    results = s.scan("https://example.com")
    caa = [r for r in results if "CAA" in r["type"] and r["status"] == "WARN"]
    assert len(caa) > 0


# ── DNS_AVAILABLE = False ─────────────────────────────────────────────────────

def test_dns_not_available_returns_empty(monkeypatch):
    monkeypatch.setattr("tblue.scanner.email_security._DNS_AVAILABLE", False)
    s = make_scanner()
    results = s.scan("https://example.com")
    assert results == []


# ── Empty domain ─────────────────────────────────────────────────────────────

def test_empty_domain_returns_empty(monkeypatch):
    monkeypatch.setattr("tblue.scanner.email_security._DNS_AVAILABLE", True)
    monkeypatch.setattr("tblue.scanner.email_security._extract_domain", lambda u: "")
    s = make_scanner()
    results = s.scan("https://example.com")
    assert results == []


# ── Weak DKIM key ─────────────────────────────────────────────────────────────

def test_dkim_weak_key_warns(monkeypatch):
    # Short p= value (< 300 chars) → est_bits < 1800 → WARN
    short_key = "A" * 50  # 50 * 6 = 300 bits — clearly under 1800
    def fake_txt(name):
        if "_domainkey.example.com" in name:
            return [f"v=DKIM1; k=rsa; p={short_key}"]
        if name == "example.com":
            return ["v=spf1 -all"]
        return []
    monkeypatch.setattr("tblue.scanner.email_security._txt_records", fake_txt)
    monkeypatch.setattr("tblue.scanner.email_security._caa_records", lambda n: [])
    s = make_scanner()
    results = s.scan("https://example.com")
    assert any("weak" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_dkim_no_p_key_in_record_passes(monkeypatch):
    # DKIM record found but p= field absent → key_match is None → skip to PASS
    def fake_txt(name):
        if "_domainkey.example.com" in name:
            return ["v=DKIM1; k=rsa"]  # no p= value → regex doesn't match
        if name == "example.com":
            return ["v=spf1 -all"]
        return []
    monkeypatch.setattr("tblue.scanner.email_security._txt_records", fake_txt)
    monkeypatch.setattr("tblue.scanner.email_security._caa_records", lambda n: [])
    s = make_scanner()
    results = s.scan("https://example.com")
    dkim = [r for r in results if "DKIM" in r["type"]]
    assert any(r["status"] == "PASS" for r in dkim)


# ── _txt_records and _caa_records implementation ──────────────────────────────

def test_txt_records_returns_empty_when_dns_unavailable(monkeypatch):
    import tblue.scanner.email_security as mod
    monkeypatch.setattr(mod, "_DNS_AVAILABLE", False)
    assert _txt_records("example.com") == []


def test_txt_records_handles_dns_exception(monkeypatch):
    import tblue.scanner.email_security as mod
    monkeypatch.setattr(mod, "_DNS_AVAILABLE", True)
    mock_resolver = MagicMock()
    mock_resolver.resolve.side_effect = Exception("NXDOMAIN")
    monkeypatch.setattr(mod, "dns", mock_resolver, raising=False)
    with patch("tblue.scanner.email_security.dns.resolver.resolve",
               side_effect=Exception("NXDOMAIN")):
        result = _txt_records("example.com")
    assert result == []


def test_txt_records_returns_decoded_strings(monkeypatch):
    import tblue.scanner.email_security as mod
    monkeypatch.setattr(mod, "_DNS_AVAILABLE", True)
    mock_rdata = MagicMock()
    mock_rdata.strings = [b"v=spf1 -all"]
    mock_answer = MagicMock()
    mock_answer.__iter__ = lambda self: iter([mock_rdata])
    with patch("tblue.scanner.email_security.dns.resolver.resolve",
               return_value=mock_answer):
        result = _txt_records("example.com")
    assert "v=spf1 -all" in result


def test_caa_records_returns_empty_when_dns_unavailable(monkeypatch):
    import tblue.scanner.email_security as mod
    monkeypatch.setattr(mod, "_DNS_AVAILABLE", False)
    assert _caa_records("example.com") == []


def test_caa_records_handles_dns_exception(monkeypatch):
    with patch("tblue.scanner.email_security.dns.resolver.resolve",
               side_effect=Exception("NXDOMAIN")):
        result = _caa_records("example.com")
    assert result == []


def test_caa_records_returns_strings(monkeypatch):
    import tblue.scanner.email_security as mod
    monkeypatch.setattr(mod, "_DNS_AVAILABLE", True)
    mock_rdata = MagicMock()
    mock_rdata.__str__ = lambda self: '0 issue "letsencrypt.org"'
    mock_answer = MagicMock()
    mock_answer.__iter__ = lambda self: iter([mock_rdata])
    with patch("tblue.scanner.email_security.dns.resolver.resolve",
               return_value=mock_answer):
        result = _caa_records("example.com")
    assert any("letsencrypt" in r for r in result)
