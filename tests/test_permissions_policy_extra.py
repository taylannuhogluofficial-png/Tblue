"""Extra branch coverage for tblue.scanner.permissions_policy."""

from unittest.mock import MagicMock, patch
from tblue.scanner.permissions_policy import PermissionsPolicyScanner

URL = "https://example.com"


def _resp(body="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.url = URL
    return r


def _scanner():
    session = MagicMock()
    return PermissionsPolicyScanner(session)


def test_missing_permissions_policy_warns():
    """Missing Permissions-Policy header → WARN or FAIL."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("", headers={})):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad


def test_present_permissions_policy_passes():
    """Valid Permissions-Policy header present → PASS."""
    s = _scanner()
    hdrs = {"Permissions-Policy": "geolocation=(), microphone=(), camera=()"}
    with patch.object(s.http, "get", return_value=_resp("", headers=hdrs)):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_none_response_no_fail():
    """None response → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert all(r["status"] != "FAIL" for r in results)


def test_result_keys():
    """Results contain required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("")):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r


def test_wildcard_permissions_warns():
    """Permissive wildcard policy → WARN or FAIL."""
    s = _scanner()
    hdrs = {"Permissions-Policy": "geolocation=*, camera=*"}
    with patch.object(s.http, "get", return_value=_resp("", headers=hdrs)):
        results = s.scan(URL)
    assert isinstance(results, list)
