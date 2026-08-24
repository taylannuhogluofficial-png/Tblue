"""Extra coverage tests for cicd_exposure — targeting lines 205, 207, 235-236."""

from unittest.mock import MagicMock, patch
from tblue.scanner.cicd_exposure import CICDExposureScanner

URL = "https://example.com"


def _make_scanner():
    return CICDExposureScanner(MagicMock())


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    r.cookies = {}
    return r


def test_cicd_fail_with_secret_ref_extra_message():
    """FAIL branch appends secret reference detail when ${{ secrets.X }} found (line 205)."""
    s = _make_scanner()
    workflow_body = """
name: Deploy
on: push
jobs:
  deploy:
    steps:
      - uses: actions/checkout@v3
      - run: deploy.sh
        env:
          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
"""
    def se(url, **kw):
        if ".github/workflows" in url or "ci.yml" in url or ".gitlab-ci.yml" in url:
            return _resp(200, workflow_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    # Should produce a FAIL with the secret ref detail
    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails, f"Expected FAIL for CI/CD with secret refs, got: {results}"


def test_cicd_fail_with_internal_infra_extra_message():
    """FAIL branch appends internal infra detail when registry.corp.internal found (line 207)."""
    s = _make_scanner()
    workflow_body = """
name: Build
on: push
jobs:
  build:
    steps:
      - run: docker pull registry.corp.internal/myapp:latest
      - run: ./build.sh
"""
    def se(url, **kw):
        if ".github/workflows" in url or "ci.yml" in url or ".gitlab-ci.yml" in url:
            return _resp(200, workflow_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    fails = [r for r in results if r["status"] == "FAIL"]
    assert fails, f"Expected FAIL for CI/CD with internal infra refs, got: {results}"


def test_cicd_warn_severity_path():
    """WARN branch fires for low-severity CI/CD files like requirements.txt (lines 235-236)."""
    s = _make_scanner()
    requirements_body = """
# Python dependencies
requests==2.31.0
flask==3.0.0
sqlalchemy==2.0.20
celery==5.3.1
"""

    def se(url, **kw):
        if "requirements.txt" in url:
            return _resp(200, requirements_body)
        if "Makefile" in url or ".dockerignore" in url or "composer.json" in url:
            return _resp(200, "# generic content here for the build system")
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    warns = [r for r in results if r["status"] == "WARN"]
    assert warns, f"Expected WARN for requirements.txt exposure, got: {results}"


def test_cicd_warn_makefile_exposure():
    """Makefile accessible produces WARN (WARN severity path)."""
    s = _make_scanner()
    makefile_body = """
.PHONY: build test deploy

build:
\tdocker build -t myapp:latest .

deploy:
\tkubectl apply -f k8s/deployment.yaml
"""

    def se(url, **kw):
        if "Makefile" in url:
            return _resp(200, makefile_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
    assert warns_or_fails, f"Expected WARN/FAIL for Makefile exposure, got: {results}"


def test_cicd_probe_exception_is_caught_and_skipped():
    """Exception during a probe is caught by the except block (lines 235-236)."""
    s = _make_scanner()
    call_count = [0]

    def se(url, **kw):
        call_count[0] += 1
        if call_count[0] == 1:
            # First call: base URL returns 200 so scan doesn't abort early
            return _resp(200, "<html></html>")
        # All probe calls raise ConnectionError — caught by except block
        raise ConnectionError("Connection reset by peer")

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)

    # All probes raised exceptions → no findings → PASS
    assert any(r["status"] == "PASS" for r in results)
