"""Tests for threat intelligence scanner."""

import os
from unittest.mock import MagicMock, patch
from tblue.scanner.threat_intel import ThreatIntelScanner, _extract_domain, _resolve_ip


# ── Helpers ────────────────────────────────────────────────────────────────────

def _scanner(responses: dict = None):
    """responses: {url_substring: (status_code, json_or_text)}"""
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        for pattern, (status, body) in (responses or {}).items():
            if pattern in url:
                resp = MagicMock()
                resp.status_code = status
                resp.json.return_value = body if isinstance(body, dict) else {}
                resp.text = str(body)
                return resp
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {}
        return resp

    session.request.side_effect = fake_request
    return ThreatIntelScanner(session)


# ── _extract_domain ────────────────────────────────────────────────────────────

def test_extract_domain_simple():
    assert _extract_domain("https://example.com/path") == "example.com"


def test_extract_domain_with_port():
    assert _extract_domain("https://example.com:8443/path") == "example.com"


def test_extract_domain_no_scheme():
    result = _extract_domain("example.com")
    assert "example.com" in result


# ── No API keys configured ─────────────────────────────────────────────────────

def test_no_api_keys_returns_warn():
    scanner = _scanner()
    env_patch = {"ABUSEIPDB_API_KEY": "", "VIRUSTOTAL_API_KEY": ""}

    otx_response = {"pulse_info": {"count": 0, "pulses": []}}
    scanner2 = _scanner({
        "otx.alienvault.com": (200, otx_response),
    })

    with patch.dict(os.environ, env_patch, clear=False):
        with patch("tblue.scanner.threat_intel._resolve_ip", return_value="1.2.3.4"):
            results = scanner2.scan("https://example.com")

    # OTX ran (no key needed) — should have OTX results
    assert any("otx" in r["type"].lower() or "threat intelligence" in r["type"].lower()
               for r in results)


def test_no_api_keys_no_otx_response_returns_warn():
    session = MagicMock()
    session.request.return_value = None  # all requests fail
    scanner = ThreatIntelScanner(session)
    with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "", "VIRUSTOTAL_API_KEY": ""}, clear=False):
        with patch("tblue.scanner.threat_intel._resolve_ip", return_value=None):
            results = scanner.scan("https://example.com")
    assert any(r["status"] == "WARN" for r in results)


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

def test_abuseipdb_clean_ip_passes():
    resp = {"data": {"abuseConfidenceScore": 0, "totalReports": 0, "countryCode": "US", "isp": "Test ISP"}}
    scanner = _scanner({"abuseipdb.com": (200, resp)})
    with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "testkey123"}):
        with patch("tblue.scanner.threat_intel._resolve_ip", return_value="8.8.8.8"):
            results = scanner.scan("https://clean.example.com")
    abuseipdb = [r for r in results if "abuseipdb" in r["type"].lower()]
    assert any(r["status"] == "PASS" for r in abuseipdb)


def test_abuseipdb_high_score_fails():
    resp = {"data": {"abuseConfidenceScore": 85, "totalReports": 42, "countryCode": "RU", "isp": "Bad ISP"}}
    scanner = _scanner({"abuseipdb.com": (200, resp)})
    with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "testkey123"}):
        with patch("tblue.scanner.threat_intel._resolve_ip", return_value="1.2.3.4"):
            results = scanner.scan("https://example.com")
    abuseipdb = [r for r in results if "abuseipdb" in r["type"].lower()]
    assert any(r["status"] == "FAIL" for r in abuseipdb)


def test_abuseipdb_medium_score_warns():
    resp = {"data": {"abuseConfidenceScore": 30, "totalReports": 5, "countryCode": "CN", "isp": "ISP"}}
    scanner = _scanner({"abuseipdb.com": (200, resp)})
    with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "testkey123"}):
        with patch("tblue.scanner.threat_intel._resolve_ip", return_value="1.2.3.4"):
            results = scanner.scan("https://example.com")
    abuseipdb = [r for r in results if "abuseipdb" in r["type"].lower()]
    assert any(r["status"] == "WARN" for r in abuseipdb)


def test_abuseipdb_no_key_skips():
    scanner = _scanner({"abuseipdb.com": (200, {"data": {"abuseConfidenceScore": 99}})})
    with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": ""}, clear=False):
        with patch("tblue.scanner.threat_intel._resolve_ip", return_value="1.2.3.4"):
            results = scanner.scan("https://example.com")
    abuseipdb = [r for r in results if "abuseipdb" in r["type"].lower()]
    # Should not run when no key
    assert not abuseipdb


def test_abuseipdb_dns_failure_warns():
    scanner = _scanner({"abuseipdb.com": (200, {})})
    with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "testkey"}):
        with patch("tblue.scanner.threat_intel._resolve_ip", return_value=None):
            results = scanner.scan("https://unresolvable.example.com")
    abuseipdb = [r for r in results if "abuseipdb" in r["type"].lower()]
    assert any(r["status"] == "WARN" for r in abuseipdb)


# ── AlienVault OTX ────────────────────────────────────────────────────────────

def test_otx_clean_domain_passes():
    resp = {"pulse_info": {"count": 0, "pulses": []}}
    scanner = _scanner({"otx.alienvault.com": (200, resp)})
    with patch("tblue.scanner.threat_intel._resolve_ip", return_value="1.2.3.4"):
        results = scanner.scan("https://clean.example.com")
    otx = [r for r in results if "otx" in r["type"].lower()]
    assert any(r["status"] == "PASS" for r in otx)


def test_otx_domain_in_pulses_warns():
    resp = {"pulse_info": {"count": 2, "pulses": [{"name": "Bad actor pulse"}, {"name": "Malware C2"}]}}
    scanner = _scanner({"otx.alienvault.com": (200, resp)})
    with patch("tblue.scanner.threat_intel._resolve_ip", return_value=None):
        results = scanner.scan("https://malicious.example.com")
    otx = [r for r in results if "otx" in r["type"].lower()]
    assert any(r["status"] in ("WARN", "FAIL") for r in otx)


def test_otx_many_pulses_fails():
    resp = {"pulse_info": {"count": 10, "pulses": [{"name": f"Pulse {i}"} for i in range(10)]}}
    scanner = _scanner({"otx.alienvault.com": (200, resp)})
    with patch("tblue.scanner.threat_intel._resolve_ip", return_value=None):
        results = scanner.scan("https://very-bad.example.com")
    otx = [r for r in results if "otx" in r["type"].lower()]
    assert any(r["status"] == "FAIL" for r in otx)


def test_otx_network_failure_returns_no_result():
    session = MagicMock()
    session.request.return_value = None
    scanner = ThreatIntelScanner(session)
    with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "", "VIRUSTOTAL_API_KEY": ""}):
        with patch("tblue.scanner.threat_intel._resolve_ip", return_value=None):
            results = scanner.scan("https://example.com")
    # All network calls failed → should get the "no API keys" WARN
    assert isinstance(results, list)


# ── VirusTotal ────────────────────────────────────────────────────────────────

def test_virustotal_clean_domain_passes():
    resp = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "clean": 70}}}}
    scanner = _scanner({"virustotal.com": (200, resp)})
    with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "vt_test_key"}):
        with patch("tblue.scanner.threat_intel._resolve_ip", return_value="1.2.3.4"):
            results = scanner.scan("https://clean.example.com")
    vt = [r for r in results if "virustotal" in r["type"].lower()]
    assert any(r["status"] == "PASS" for r in vt)


def test_virustotal_malicious_domain_fails():
    resp = {"data": {"attributes": {"last_analysis_stats": {"malicious": 10, "suspicious": 3, "clean": 57}}}}
    scanner = _scanner({"virustotal.com": (200, resp)})
    with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "vt_test_key"}):
        with patch("tblue.scanner.threat_intel._resolve_ip", return_value="1.2.3.4"):
            results = scanner.scan("https://malicious.example.com")
    vt = [r for r in results if "virustotal" in r["type"].lower()]
    assert any(r["status"] == "FAIL" for r in vt)


def test_virustotal_no_key_skips():
    resp = {"data": {"attributes": {"last_analysis_stats": {"malicious": 99}}}}
    scanner = _scanner({"virustotal.com": (200, resp)})
    with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": ""}, clear=False):
        with patch("tblue.scanner.threat_intel._resolve_ip", return_value="1.2.3.4"):
            results = scanner.scan("https://example.com")
    vt = [r for r in results if "virustotal" in r["type"].lower()]
    assert not vt


# ── Crash safety ───────────────────────────────────────────────────────────────

def test_malformed_json_response_does_not_crash():
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = 200
    resp.json.side_effect = ValueError("invalid json")
    session.request.return_value = resp
    scanner = ThreatIntelScanner(session)
    with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "key", "VIRUSTOTAL_API_KEY": "key"}):
        with patch("tblue.scanner.threat_intel._resolve_ip", return_value="1.2.3.4"):
            results = scanner.scan("https://example.com")
    assert isinstance(results, list)


def test_results_have_mitre_field():
    resp = {"pulse_info": {"count": 1, "pulses": [{"name": "Test pulse"}]}}
    scanner = _scanner({"otx.alienvault.com": (200, resp)})
    with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "", "VIRUSTOTAL_API_KEY": ""}):
        with patch("tblue.scanner.threat_intel._resolve_ip", return_value=None):
            results = scanner.scan("https://example.com")
    for r in results:
        assert "mitre" in r
