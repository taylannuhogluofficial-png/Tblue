"""Extra branch coverage for tblue.scanner.exposure."""

from unittest.mock import MagicMock, patch
from tblue.scanner.exposure import ExposureScanner

URL = "https://example.com"


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


def _scanner():
    session = MagicMock()
    return ExposureScanner(session)


def test_all_probes_404_passes():
    """Branch: all probes return 404 — PASS (no exposed files)."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(404, "")):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    assert all(r["status"] not in ("FAIL", "WARN") for r in results)


def test_swagger_json_exposed_fails():
    """Branch: /swagger.json returns 200 — FAIL (API spec exposed)."""
    s = _scanner()
    swagger_body = '{"swagger":"2.0","info":{"title":"API","version":"1.0"},"paths":{}}'

    def side_effect(url, **kwargs):
        if "swagger.json" in url:
            return _resp(200, swagger_body)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
    assert any("swagger" in r["type"].lower() or "api" in r["type"].lower() for r in fails)


def test_package_json_exposed_warns():
    """Branch: /package.json returns 200 — WARN (dependency manifest exposed)."""
    s = _scanner()
    pkg_body = '{"name":"myapp","version":"1.0.0","dependencies":{"express":"4.18.0"}}'

    def side_effect(url, **kwargs):
        if url.endswith("/package.json"):
            return _resp(200, pkg_body)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("package" in r["type"].lower() or "depend" in r["type"].lower() for r in warns)


def test_gitlab_ci_exposed_warns():
    """Branch: /.gitlab-ci.yml returns 200 — WARN (CI/CD config exposed)."""
    s = _scanner()
    ci_body = "stages:\n  - build\n  - deploy\n\nbuild:\n  script:\n    - npm run build\n"

    def side_effect(url, **kwargs):
        if ".gitlab-ci.yml" in url:
            return _resp(200, ci_body)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns
    assert any("ci" in r["type"].lower() or "cicd" in r["type"].lower()
               or "pipeline" in r["type"].lower() for r in warns)


def test_non_200_status_not_flagged():
    """Branch: probe returns 403 Forbidden — not counted as exposed."""
    s = _scanner()
    with patch.object(s.http, "get", return_value=_resp(403, "Forbidden")):
        results = s.scan(URL)
    assert isinstance(results, list)
    fails_warns = [r for r in results if r["status"] in ("FAIL", "WARN")]
    assert not fails_warns


def test_openapi_json_exposed_fails():
    """Branch: /openapi.json returns 200 — FAIL."""
    s = _scanner()
    body = '{"openapi":"3.0.0","info":{"title":"API","version":"1.0"},"paths":{}}'

    def side_effect(url, **kwargs):
        if "openapi.json" in url:
            return _resp(200, body)
        return _resp(404, "")

    with patch.object(s.http, "get", side_effect=side_effect):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails
