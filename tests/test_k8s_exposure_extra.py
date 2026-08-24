"""Extra branch coverage for tblue.scanner.k8s_exposure."""

import json
from unittest.mock import MagicMock, patch
from tblue.scanner.k8s_exposure import K8sExposureScanner

URL = "https://example.com"


def _resp(body="", status=200):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    r.url = URL
    return r


def _scanner():
    session = MagicMock()
    return K8sExposureScanner(session)


def test_all_paths_404_passes():
    """All K8s paths return 404 → no FAIL results."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("", 404)):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_k8s_namespace_list_exposed_fails():
    """Exposed /api/v1/namespaces endpoint → FAIL."""
    s = _scanner()
    k8s_resp = json.dumps({"kind": "NamespaceList", "items": [{"metadata": {"name": "default"}}]})

    def get_side(url, **kw):
        if "/api/v1/namespaces" in url:
            return _resp(k8s_resp, 200)
        return _resp("", 404)

    with patch.object(s.http, "get", side_effect=get_side):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails


def test_k8s_version_endpoint_warns():
    """Exposed /version endpoint → WARN."""
    s = _scanner()
    version_body = json.dumps({
        "major": "1", "minor": "27",
        "gitVersion": "v1.27.0"
    })

    def get_side(url, **kw):
        if "/version" in url:
            return _resp(version_body, 200)
        return _resp("", 404)

    with patch.object(s.http, "get", side_effect=get_side):
        results = s.scan(URL)
    bad = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert bad


def test_none_response_no_crash():
    """None response → empty or PASS results, no exception."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert isinstance(results, list)
    assert all(r["status"] != "FAIL" for r in results)


def test_result_keys():
    """Results contain required keys."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp("", 404)):
        results = s.scan(URL)
    for r in results:
        assert "url" in r and "status" in r and "type" in r
