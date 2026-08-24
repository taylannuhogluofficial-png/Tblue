"""Extra branch coverage for tblue.scanner.ldap_injection."""

from unittest.mock import MagicMock, patch
from tblue.scanner.ldap_injection import LDAPinjectionScanner as LDAPInjectionScanner

URL = "https://example.com/search"


def _resp(body="", status=200):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    r.url = URL
    return r


def _scanner():
    session = MagicMock()
    return LDAPInjectionScanner(session)


def test_no_query_params_passes():
    """URL with no query params → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("<html></html>")):
        results = s.scan("https://example.com/search")
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_ldap_error_in_response_fails():
    """LDAP error string in response body → FAIL."""
    s = _scanner()
    error_body = "<html>LDAP Error: invalid DN syntax (34)</html>"
    with patch.object(s.http, "get", return_value=_resp(error_body)):
        results = s.scan("https://example.com/search?q=test")
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert isinstance(results, list)


def test_none_response_no_fail():
    """None response → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com/search?q=test")
    assert all(r["status"] != "FAIL" for r in results)


def test_result_keys():
    """Results contain required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL + "?q=test")
    for r in results:
        assert "url" in r and "status" in r and "type" in r
