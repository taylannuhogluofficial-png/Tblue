"""Tests for tblue.scanner.k8s_exposure — Kubernetes API exposure scanner."""

import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.k8s_exposure import K8sExposureScanner


def _scanner():
    session = MagicMock()
    return K8sExposureScanner(session)


def _resp(status=200, body=""):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {"content-type": "application/json"}
    return r


def _404():
    return _resp(status=404, body="")


_K8S_NAMESPACES = '{"kind":"NamespaceList","apiVersion":"v1","items":[{"metadata":{"name":"default"}}]}'
_K8S_API_ROOT = '{"kind":"APIVersions","versions":["v1"],"serverAddressByClientCIDRs":[]}'
_K8S_VERSION = '{"major":"1","minor":"28","gitVersion":"v1.28.0","gitCommit":"abc"}'


def test_no_k8s_pass():
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(200, "<html>Hello</html>")):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_namespace_list_exposed_fail():
    s = _scanner()
    def side_effect(url, **kw):
        if "/api/v1/namespaces" in url:
            return _resp(200, _K8S_NAMESPACES)
        return _resp(200, "<html></html>")
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("namespace" in r["type"].lower() for r in fails)


def test_k8s_version_exposed_warn():
    s = _scanner()
    def side_effect(url, **kw):
        if "/version" in url and "namespaces" not in url:
            return _resp(200, _K8S_VERSION)
        return _resp(200, "<html></html>")
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_anonymous_access_fail():
    s = _scanner()
    anon_body = _K8S_NAMESPACES + '"username":"system:anonymous"'
    def side_effect(url, **kw):
        if "/api/v1/namespaces" in url:
            return _resp(200, anon_body)
        return _resp(200, "<html></html>")
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_k8s_api_root_warn():
    s = _scanner()
    def side_effect(url, **kw):
        if url.endswith("/api"):
            return _resp(200, _K8S_API_ROOT)
        return _resp(200, "<html></html>")
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_no_response():
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_exception_skipped():
    s = _scanner()
    call_count = 0
    def side_effect(url, **kw):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return _resp(200, "<html></html>")
        raise ConnectionError("refused")
    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)


def test_k8s_api_on_main_page_warn():
    s = _scanner()
    body = '{"kind":"APIGroupList","apiVersion":"v1","groups":[]}'
    with patch.object(s.http, "get", return_value=_resp(200, body)):
        results = s.scan("https://example.com")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("kubernetes" in r["type"].lower() or "K8s" in r["type"] for r in warns)
