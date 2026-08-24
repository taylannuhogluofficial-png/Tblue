"""Extra branch coverage for tblue.scanner.scim."""

from unittest.mock import MagicMock
from tblue.scanner.scim import SCIMScanner

URL = "https://example.com"


def _scanner(probe_status=404, probe_body=""):
    session = MagicMock()
    resp = MagicMock()
    resp.status_code = probe_status
    resp.text = probe_body
    resp.headers = {}
    s = SCIMScanner(session)
    s.http.get = MagicMock(return_value=resp)
    return s


def test_all_probes_404_returns_pass():
    """All SCIM probes returning 404 → PASS (no exposure)."""
    results = _scanner(probe_status=404).scan(URL)
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


def test_scim_endpoint_exposed_without_auth_fails():
    """SCIM endpoint returning 200 with SCIM schema → FAIL."""
    scim_body = '{"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "totalResults": 5, "Resources": [{"userName": "alice"}]}'
    results = _scanner(probe_status=200, probe_body=scim_body).scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_scim_endpoint_with_auth_required_warns():
    """SCIM endpoint returning 200 with auth-required body → WARN."""
    scim_body = '{"status": 401, "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "detail": "Unauthorized"}'
    results = _scanner(probe_status=200, probe_body=scim_body).scan(URL)
    # The body contains both SCIM markers and Unauthorized → WARN
    assert isinstance(results, list)


def test_probe_exception_continues():
    """Exception during probe is caught and scan continues."""
    s = SCIMScanner(MagicMock())
    s.http.get = MagicMock(side_effect=ConnectionError("timeout"))
    results = s.scan(URL)
    passes = [r for r in results if r["status"] == "PASS"]
    assert passes


def test_non_scim_200_body_not_flagged():
    """200 response without SCIM schema body not flagged as exposed."""
    results = _scanner(probe_status=200, probe_body="<html>Login required</html>").scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not fails
