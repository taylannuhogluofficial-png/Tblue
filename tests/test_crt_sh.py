"""Tests for Certificate Transparency (crt.sh) scanner."""

import json
from unittest.mock import MagicMock
from tblue.scanner.crt_sh import CRTShScanner


def _scanner(crt_response=None, status=200):
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        resp.status_code = status
        if crt_response is not None:
            resp.text = json.dumps(crt_response)
            resp.json.return_value = crt_response
        else:
            resp.text = "[]"
            resp.json.return_value = []
        return resp

    session.request.side_effect = fake_request
    return CRTShScanner(session)


def test_subdomains_found_passes():
    data = [
        {"name_value": "api.example.com"},
        {"name_value": "staging.example.com"},
        {"name_value": "dev.example.com"},
    ]
    scanner = _scanner(crt_response=data)
    results = scanner.scan("https://example.com")
    assert any("subdomains found" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_subdomain_count_in_detail():
    data = [{"name_value": "api.example.com\ndev.example.com"}]
    scanner = _scanner(crt_response=data)
    results = scanner.scan("https://example.com")
    r = next(r for r in results if "subdomains found" in r["type"].lower())
    assert "api.example.com" in r["detail"] or "2" in r["detail"] or "dev" in r["detail"]


def test_no_subdomains_passes():
    data = [{"name_value": "example.com"}]  # only apex, no subs
    scanner = _scanner(crt_response=data)
    results = scanner.scan("https://example.com")
    assert any("no additional" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_wildcard_subdomains_excluded():
    data = [{"name_value": "*.example.com\napi.example.com"}]
    scanner = _scanner(crt_response=data)
    results = scanner.scan("https://example.com")
    # Wildcard shouldn't inflate the subdomain list
    r = next((r for r in results if "subdomains found" in r["type"].lower()), None)
    if r:
        assert "*" not in r["detail"]


def test_apex_domain_excluded_from_subs():
    data = [{"name_value": "example.com"}]
    scanner = _scanner(crt_response=data)
    results = scanner.scan("https://example.com")
    # Apex domain only — should produce 'no additional subdomains' PASS
    assert any("no additional" in r["type"].lower() and r["status"] == "PASS"
               for r in results)


def test_crt_sh_error_returns_empty():
    scanner = _scanner(status=500)
    results = scanner.scan("https://example.com")
    assert results == []


def test_crt_sh_network_error_returns_empty():
    session = MagicMock()
    session.request.side_effect = Exception("timeout")
    scanner = CRTShScanner(session)
    results = scanner.scan("https://example.com")
    assert results == []


def test_subdomains_stored_in_extra():
    data = [{"name_value": "api.example.com\ndev.example.com"}]
    scanner = _scanner(crt_response=data)
    results = scanner.scan("https://example.com")
    r = next((r for r in results if "subdomains found" in r["type"].lower()), None)
    assert r is not None
    assert "ct_subdomains" in r
    assert "api.example.com" in r["ct_subdomains"]


def test_unrelated_domains_excluded():
    # crt.sh sometimes returns certs for other domains that share a SAN
    data = [{"name_value": "api.example.com\nother-site.com"}]
    scanner = _scanner(crt_response=data)
    results = scanner.scan("https://example.com")
    r = next((r for r in results if r.get("ct_subdomains")), None)
    if r:
        assert "other-site.com" not in r["ct_subdomains"]
