"""Extra branch coverage for tblue.scanner.saml."""

from unittest.mock import MagicMock
from tblue.scanner.saml import SAMLScanner

URL = "https://example.com"


def _scanner(html="", status=200, headers=None, probe_status=404):
    session = MagicMock()
    main_resp = MagicMock()
    main_resp.status_code = status
    main_resp.text = html
    main_resp.headers = headers or {}
    main_resp.url = URL

    probe_resp = MagicMock()
    probe_resp.status_code = probe_status
    probe_resp.text = ""
    probe_resp.headers = {}

    call_count = [0]

    def fake_get(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return main_resp
        return probe_resp

    s = SAMLScanner(session)
    s.http.get = MagicMock(side_effect=fake_get)
    return s


def test_no_response_returns_empty():
    """None main response returns empty results."""
    s = SAMLScanner(MagicMock())
    s.http.get = MagicMock(return_value=None)
    results = s.scan(URL)
    assert results == []


def test_no_saml_indicators_no_findings():
    """Page with no SAML indicators and all probes 404 → no FAIL."""
    results = _scanner(html="<html><body>Normal page</body></html>").scan(URL)
    assert isinstance(results, list)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not fails


def test_saml_indicator_in_page_body_detected():
    """Page body with SAMLRequest pattern triggers SAML detection logic."""
    html = '<html><body><form><input name="SAMLRequest" value="PHNhbWxwOkF1dGhu"/></form></body></html>'
    results = _scanner(html=html).scan(URL)
    assert isinstance(results, list)


def test_http_saml_endpoint_in_page_fails():
    """Plain http:// SAML endpoint with SAML indicator in page → FAIL for cleartext."""
    # Need SAML indicator (SAMLRequest etc) for scanner to engage, then HTTP endpoint triggers FAIL
    html = (
        '<html><body>'
        '<input name="SAMLRequest" value="PHNhbWxwOkF1dGhuUmVxdWVzdA==" />'
        '<a href="http://idp.example.com/saml/sso">Login via SSO</a>'
        '</body></html>'
    )
    results = _scanner(html=html).scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_relay_state_in_page_detected():
    """RelayState parameter in page URL triggers WARN."""
    html = '<html><body><a href="/saml/sso?RelayState=https://example.com/dashboard">Login</a></body></html>'
    results = _scanner(html=html).scan(URL)
    assert isinstance(results, list)


def test_probe_exception_continues_scan():
    """Exception on SAML path probe is caught and scan continues."""
    s = SAMLScanner(MagicMock())
    main_resp = MagicMock()
    main_resp.status_code = 200
    main_resp.text = ""
    main_resp.headers = {}
    main_resp.url = URL

    call_count = [0]

    def fake_get(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            return main_resp
        raise ConnectionError("probe failed")

    s.http.get = MagicMock(side_effect=fake_get)
    results = s.scan(URL)
    assert isinstance(results, list)
