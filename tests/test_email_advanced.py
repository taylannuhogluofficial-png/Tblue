"""Tests for advanced email security scanner (MTA-STS, BIMI, DANE, SPF, DMARC depth)."""

from unittest.mock import MagicMock, patch
from tblue.scanner.email_advanced import (
    EmailAdvancedScanner, _resolve_txt, _count_spf_lookups,
)


def make_scanner():
    session = MagicMock()
    resp    = MagicMock()
    resp.status_code = 200
    resp.text        = "version: STSv1\nmode: enforce\nmx: mail.example.com"
    session.request.return_value = resp
    return EmailAdvancedScanner(session)


def _resolver_with_txt(records: dict):
    """Return a fake dns.resolver-like object with preset TXT records."""
    resolver = MagicMock()
    def fake_resolve(name, rdtype):
        key = (name.lower(), rdtype.upper())
        if key in records:
            rdata_list = []
            for val in records[key]:
                rdata = MagicMock()
                rdata.strings = [val.encode()]
                rdata_list.append(rdata)
            return rdata_list
        raise Exception(f"NXDOMAIN: {name}")
    resolver.resolve.side_effect = fake_resolve
    return resolver


# ── MTA-STS ───────────────────────────────────────────────────────────────────

def test_mta_sts_missing_warns(monkeypatch):
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (_resolver_with_txt({}), MagicMock()))
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("mta-sts" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_mta_sts_configured_passes(monkeypatch):
    records = {
        ("_mta-sts.example.com", "TXT"): ["v=STSv1; id=20231001"],
    }
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (_resolver_with_txt(records), MagicMock()))
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("mta-sts" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ── TLS-RPT ───────────────────────────────────────────────────────────────────

def test_tls_rpt_missing_warns(monkeypatch):
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (_resolver_with_txt({}), MagicMock()))
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("tls-rpt" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_tls_rpt_configured_passes(monkeypatch):
    records = {
        ("_smtp._tls.example.com", "TXT"): ["v=TLSRPTv1; rua=mailto:tls@example.com"],  # contains "v=tlsrptv1"
    }
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (_resolver_with_txt(records), MagicMock()))
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("tls-rpt" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ── BIMI ──────────────────────────────────────────────────────────────────────

def test_bimi_missing_warns(monkeypatch):
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (_resolver_with_txt({}), MagicMock()))
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("bimi" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_bimi_configured_passes(monkeypatch):
    records = {
        ("default._bimi.example.com", "TXT"): ["v=BIMI1; l=https://example.com/logo.svg"],
    }
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (_resolver_with_txt(records), MagicMock()))
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("bimi" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ── SPF strictness ────────────────────────────────────────────────────────────

def test_spf_strict_all_passes(monkeypatch):
    records = {("example.com", "TXT"): ["v=spf1 include:mailgun.org -all"]}
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (_resolver_with_txt(records), MagicMock()))
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("spf strict" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_spf_plus_all_fails(monkeypatch):
    records = {("example.com", "TXT"): ["v=spf1 include:mailgun.org +all"]}
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (_resolver_with_txt(records), MagicMock()))
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("+all" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_spf_softfail_warns(monkeypatch):
    records = {("example.com", "TXT"): ["v=spf1 include:mailgun.org ~all"]}
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (_resolver_with_txt(records), MagicMock()))
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("softfail" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── DMARC depth ───────────────────────────────────────────────────────────────

def test_dmarc_none_warns(monkeypatch):
    records = {
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none; rua=mailto:dmarc@example.com"]
    }
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (_resolver_with_txt(records), MagicMock()))
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("none" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_dmarc_reject_passes(monkeypatch):
    records = {
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
    }
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (_resolver_with_txt(records), MagicMock()))
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("fully enforced" in r["type"].lower() and r["status"] == "PASS" for r in results)


def test_dmarc_partial_pct_warns(monkeypatch):
    records = {
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=reject; pct=50; rua=mailto:d@e.com"]
    }
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (_resolver_with_txt(records), MagicMock()))
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("pct=50" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_no_dnspython_returns_empty(monkeypatch):
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (None, None))
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert results == []


# ── Direct _import_dns call ───────────────────────────────────────────────────

def test_import_dns_returns_modules():
    from tblue.scanner.email_advanced import _import_dns
    resolver, exception = _import_dns()
    assert resolver is not None


# ── Empty domain returns early ─────────────────────────────────────────────────

def test_empty_domain_returns_empty(monkeypatch):
    resolver = _resolver_with_txt({})
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (resolver, MagicMock()))
    scanner = make_scanner()
    results = scanner.scan("")  # empty URL → empty domain
    assert results == []


# ── MTA-STS policy file missing/invalid ──────────────────────────────────────

def test_mta_sts_dns_present_but_policy_file_bad(monkeypatch):
    records = {
        ("_mta-sts.example.com", "TXT"): ["v=STSv1; id=20231001"],
    }
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (_resolver_with_txt(records), MagicMock()))
    # Policy file response is invalid (no "version: stsv1" text)
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = 200
    resp.text = "This is not an MTA-STS policy"
    session.request.return_value = resp
    scanner = EmailAdvancedScanner(session)
    results = scanner.scan("https://example.com")
    assert any("policy file" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_mta_sts_policy_file_exception(monkeypatch):
    from unittest.mock import patch
    records = {
        ("_mta-sts.example.com", "TXT"): ["v=STSv1; id=20231001"],
    }
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (_resolver_with_txt(records), MagicMock()))
    scanner = make_scanner()
    # Patch the HTTP get directly to raise (bypasses the retry wrapper)
    with patch.object(scanner.http, "get", side_effect=Exception("connection refused")):
        results = scanner.scan("https://example.com")
    assert any("unreachable" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── DANE/TLSA configured ──────────────────────────────────────────────────────

def test_dane_configured_passes(monkeypatch):
    resolver = MagicMock()
    def fake_resolve(name, rdtype):
        if rdtype == "TLSA":
            answer = MagicMock()
            answer.__bool__ = lambda self: True
            return answer
        raise Exception("NXDOMAIN")
    resolver.resolve.side_effect = fake_resolve
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (resolver, MagicMock()))
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = 404
    resp.text = ""
    session.request.return_value = resp
    scanner = EmailAdvancedScanner(session)
    results = scanner.scan("https://example.com")
    assert any("dane" in r["type"].lower() and r["status"] == "PASS" for r in results)


# ── SPF neutral (?all) ────────────────────────────────────────────────────────

def test_spf_neutral_all_warns(monkeypatch):
    records = {("example.com", "TXT"): ["v=spf1 include:mailgun.org ?all"]}
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (_resolver_with_txt(records), MagicMock()))
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("?all" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── SPF with no _all qualifier ────────────────────────────────────────────────

def test_spf_no_all_qualifier_skips_qualifier_check(monkeypatch):
    # SPF record without +/-/~/? all → no qualifier result
    records = {("example.com", "TXT"): ["v=spf1 include:mailgun.org"]}
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (_resolver_with_txt(records), MagicMock()))
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    # No qualifier result expected — just no crash
    assert isinstance(results, list)


# ── SPF lookup count approaching limit ────────────────────────────────────────

def test_spf_approaching_lookup_limit_warns(monkeypatch):
    # Use a deeply nested include: chain to hit count > 7 but <= 10
    # Simplified: patch _count_spf_lookups to return 8
    from unittest.mock import patch
    records = {("example.com", "TXT"): ["v=spf1 include:mailgun.org -all"]}
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (_resolver_with_txt(records), MagicMock()))
    scanner = make_scanner()
    with patch("tblue.scanner.email_advanced._count_spf_lookups", return_value=8):
        results = scanner.scan("https://example.com")
    assert any("approaching" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_spf_lookup_limit_exceeded_warns(monkeypatch):
    from unittest.mock import patch
    records = {("example.com", "TXT"): ["v=spf1 include:mailgun.org -all"]}
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (_resolver_with_txt(records), MagicMock()))
    scanner = make_scanner()
    with patch("tblue.scanner.email_advanced._count_spf_lookups", return_value=12):
        results = scanner.scan("https://example.com")
    assert any("lookup limit exceeded" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_spf_lookup_count_exception_silent(monkeypatch):
    from unittest.mock import patch
    records = {("example.com", "TXT"): ["v=spf1 include:mailgun.org -all"]}
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (_resolver_with_txt(records), MagicMock()))
    scanner = make_scanner()
    with patch("tblue.scanner.email_advanced._count_spf_lookups",
               side_effect=Exception("recursion error")):
        results = scanner.scan("https://example.com")
    # Should not crash
    assert isinstance(results, list)


# ── _count_spf_lookups recursion ──────────────────────────────────────────────

def test_count_spf_lookups_depth_limit():
    resolver = MagicMock()
    resolver.resolve.side_effect = Exception("NXDOMAIN")
    from tblue.scanner.email_advanced import _count_spf_lookups
    # depth > 5 → returns 0
    result = _count_spf_lookups(resolver, "v=spf1 include:mailgun.org -all", depth=6)
    assert result == 0


def test_count_spf_lookups_with_include_recursion():
    records_map = {
        ("mailgun.org", "TXT"): ["v=spf1 -all"]
    }
    resolver = MagicMock()
    def fake_resolve(name, rdtype):
        key = (name.lower(), rdtype.upper())
        if key in records_map:
            rdata_list = []
            for val in records_map[key]:
                rdata = MagicMock()
                rdata.strings = [val.encode()]
                rdata_list.append(rdata)
            return rdata_list
        raise Exception(f"NXDOMAIN: {name}")
    resolver.resolve.side_effect = fake_resolve
    from tblue.scanner.email_advanced import _count_spf_lookups
    count = _count_spf_lookups(resolver, "v=spf1 include:mailgun.org -all")
    assert count >= 1  # at least 1 lookup mechanism


# ── DMARC quarantine ──────────────────────────────────────────────────────────

def test_dmarc_quarantine_warns(monkeypatch):
    records = {
        ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=quarantine; rua=mailto:d@e.com"]
    }
    monkeypatch.setattr("tblue.scanner.email_advanced._import_dns",
                        lambda: (_resolver_with_txt(records), MagicMock()))
    scanner = make_scanner()
    results = scanner.scan("https://example.com")
    assert any("quarantine" in r["type"].lower() and r["status"] == "WARN" for r in results)
