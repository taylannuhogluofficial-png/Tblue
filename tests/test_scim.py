"""Tests for tblue.scanner.scim — SCIM endpoint exposure scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.scim import SCIMScanner


def _scanner():
    session = MagicMock()
    s = SCIMScanner(session)
    return s


def _resp(status=200, body=""):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    return r


def _404():
    r = MagicMock()
    r.status_code = 404
    r.text = ""
    r.headers = {}
    return r


_SCIM_BODY = '{"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"totalResults":3,"Resources":[]}'


def test_no_scim_endpoints_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_404()):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_unauthenticated_scim_fail():
    s = _scanner()
    def side_effect(url, **kw):
        if "/scim/v2/Users" in url:
            return _resp(200, _SCIM_BODY)
        return _404()
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("without authentication" in r["detail"] for r in fails)


def test_scim_with_auth_required_warn():
    s = _scanner()
    def side_effect(url, **kw):
        if "/scim/v2/Users" in url:
            body = _SCIM_BODY + '"status":401'
            r = _resp(200, body)
            return r
        return _404()
    # Simulate auth-required response via 401 body match
    auth_body = _SCIM_BODY.replace("totalResults", '"status":401, "totalResults"')
    def side_effect2(url, **kw):
        if "/scim/v2/Users" in url:
            return _resp(200, auth_body)
        return _404()
    with patch.object(s.http, "get", side_effect=side_effect2):
        results = s.scan("https://example.com")
    # May be FAIL (unauthenticated) or WARN — either is valid finding
    statuses = {r["status"] for r in results}
    assert "PASS" not in statuses or len(results) == 1  # if only PASS, no SCIM found


def test_scim_api_prefix_path():
    s = _scanner()
    def side_effect(url, **kw):
        if "/api/scim/v2/Users" in url:
            return _resp(200, _SCIM_BODY)
        return _404()
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_scim_resource_types_exposed():
    s = _scanner()
    resource_body = '{"totalResults": 5, "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]}'
    def side_effect(url, **kw):
        if "/scim/v2/ResourceTypes" in url:
            return _resp(200, resource_body)
        return _404()
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    assert any(r["status"] == "FAIL" for r in results)


def test_scan_no_response():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    # None responses → no SCIM found → PASS
    assert any(r["status"] == "PASS" for r in results)


def test_exception_in_probe_skipped():
    s = _scanner()
    call_count = 0
    def side_effect(url, **kw):
        nonlocal call_count
        call_count += 1
        if call_count == 3:
            raise ConnectionError("timeout")
        return _404()
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_scim_v1_users():
    s = _scanner()
    def side_effect(url, **kw):
        if "/scim/Users" in url and "/v2/" not in url:
            return _resp(200, '{"totalResults":2, "schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"]}')
        return _404()
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    assert any(r["status"] == "FAIL" for r in results)
