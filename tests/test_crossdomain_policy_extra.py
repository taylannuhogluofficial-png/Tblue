"""Extra branch coverage for tblue.scanner.crossdomain_policy."""

from unittest.mock import MagicMock, patch
from tblue.scanner.crossdomain_policy import CrossDomainPolicyScanner

URL = "https://example.com"


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _scanner():
    session = MagicMock()
    return CrossDomainPolicyScanner(session)


def test_all_files_missing_returns_pass():
    """Branch: all four policy files return 404 — no findings."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(404, "")):
        results = s.scan(URL)
    assert isinstance(results, list)
    # No FAIL when none present
    assert all(r["status"] != "FAIL" for r in results)


def test_crossdomain_xml_wildcard_domain_fails():
    """Branch: crossdomain.xml with allow-access-from domain='*' — FAIL."""
    s = _scanner()
    crossdomain_body = (
        '<?xml version="1.0"?>\n'
        '<cross-domain-policy>\n'
        '  <allow-access-from domain="*"/>\n'
        '</cross-domain-policy>'
    )

    def side_effect(url, **kwargs):
        if "crossdomain.xml" in url:
            return _resp(200, crossdomain_body)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("crossdomain" in r["type"].lower() or "wildcard" in r["type"].lower() for r in fails)


def test_clientaccess_wildcard_uri_warns_or_fails():
    """Branch: clientaccesspolicy.xml with domain uri='*' — WARN or FAIL."""
    s = _scanner()
    body = (
        '<access-policy>\n'
        '  <cross-domain-access>\n'
        '    <policy>\n'
        '      <allow-from>\n'
        '        <domain uri="*"/>\n'
        '      </allow-from>\n'
        '    </policy>\n'
        '  </cross-domain-access>\n'
        '</access-policy>'
    )

    def side_effect(url, **kwargs):
        if "clientaccesspolicy.xml" in url:
            return _resp(200, body)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad


def test_crossdomain_xml_present_but_restrictive_is_not_fail():
    """Branch: crossdomain.xml with no wildcard domain — no FAIL."""
    s = _scanner()
    body = (
        '<?xml version="1.0"?>\n'
        '<cross-domain-policy>\n'
        '  <site-control permitted-cross-domain-policies="master-only"/>\n'
        '  <allow-access-from domain="trusted.example.com"/>\n'
        '</cross-domain-policy>'
    )

    def side_effect(url, **kwargs):
        if "crossdomain.xml" in url:
            return _resp(200, body)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan(URL)
    # Should not produce FAIL for wildcard; may produce informational results
    assert isinstance(results, list)
    fail_msgs = [r for r in results if r["status"] == "FAIL" and "wildcard" in r["type"].lower()]
    assert not fail_msgs


def test_crossdomain_secure_false_warns():
    """Branch: allow-access-from with secure='false' — WARN."""
    s = _scanner()
    body = (
        '<?xml version="1.0"?>\n'
        '<cross-domain-policy>\n'
        '  <allow-access-from domain="example.com" secure="false"/>\n'
        '</cross-domain-policy>'
    )

    def side_effect(url, **kwargs):
        if "crossdomain.xml" in url:
            return _resp(200, body)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_none_response_is_handled():
    """Branch: http.get returns None for all probes — no exceptions, returns list."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert isinstance(results, list)
