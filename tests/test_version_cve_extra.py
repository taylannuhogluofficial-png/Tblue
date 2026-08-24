"""Extra branch coverage for tblue.scanner.version_cve."""

from unittest.mock import MagicMock, patch
from tblue.scanner.version_cve import VersionCVEScanner

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
    return VersionCVEScanner(session)


def test_no_server_header_passes():
    """No Server header → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("", headers={})):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_server_header_with_version_warns():
    """Server: Apache/2.4.49 → WARN (version disclosed)."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("", headers={"Server": "Apache/2.4.49"})):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad


def test_x_powered_by_with_version_warns():
    """X-Powered-By: PHP/7.4.3 → WARN (version disclosed)."""
    s = _scanner()
    hdrs = {"X-Powered-By": "PHP/7.4.3"}
    with patch.object(s.http, "get", return_value=_resp("", headers=hdrs)):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad


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
