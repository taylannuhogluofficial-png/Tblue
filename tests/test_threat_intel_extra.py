"""Extra branch coverage for tblue.scanner.threat_intel."""

import json
import socket
from unittest.mock import MagicMock, patch
from tblue.scanner.threat_intel import ThreatIntelScanner

URL = "https://example.com"


def _otx_clean_resp():
    """Mock response for OTX domain/IP indicator — zero pulses (clean)."""
    r = MagicMock()
    r.status_code = 200
    data = {"pulse_info": {"count": 0, "pulses": []}, "reputation": 0}
    r.text = json.dumps(data)
    r.headers = {}
    r.url = URL
    r.json = MagicMock(return_value=data)
    return r


def _scanner():
    session = MagicMock()
    return ThreatIntelScanner(session)


def test_no_api_keys_with_clean_otx_passes():
    """Without ABUSEIPDB/VT keys, scanner only runs OTX checks; clean OTX → PASS."""
    s = _scanner()
    with patch.dict("os.environ", {}, clear=True), \
         patch("socket.gethostbyname", return_value="93.184.216.34"), \
         patch.object(s.http, "get", return_value=_otx_clean_resp()):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_abuseipdb_clean_ip_passes(monkeypatch):
    """AbuseIPDB returns score < 25 → PASS."""
    s = _scanner()
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "testkey")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    data = {"data": {"abuseConfidenceScore": 0, "totalReports": 0, "countryCode": "US", "isp": "CF"}}
    mock_resp.json = MagicMock(return_value=data)
    mock_resp.headers = {}

    with patch("socket.gethostbyname", return_value="93.184.216.34"), \
         patch.object(s.http, "get", return_value=mock_resp):
        results = s.scan(URL)
    pass_results = [r for r in results if r["status"] == "PASS"]
    assert pass_results


def test_abuseipdb_malicious_ip_fails(monkeypatch):
    """AbuseIPDB returns score >= 50 → FAIL."""
    s = _scanner()
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "testkey")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    data = {"data": {"abuseConfidenceScore": 85, "totalReports": 47, "countryCode": "RU", "isp": "Bad"}}
    mock_resp.json = MagicMock(return_value=data)
    mock_resp.headers = {}

    with patch("socket.gethostbyname", return_value="192.0.2.1"), \
         patch.object(s.http, "get", return_value=mock_resp):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_dns_failure_gracefully_handled():
    """DNS resolution failure → WARN or PASS (not an uncaught exception)."""
    s = _scanner()
    with patch("socket.gethostbyname", side_effect=OSError("No such host")), \
         patch.object(s.http, "get", return_value=_otx_clean_resp()):
        results = s.scan(URL)
    assert isinstance(results, list)
    # No exception should have been raised
