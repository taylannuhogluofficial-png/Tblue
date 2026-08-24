"""Tests for tblue.scanner.cicd_exposure — CICDExposureScanner."""

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


def test_no_cicd_files_pass():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=_resp(404)):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] == "FAIL" for r in results)


def test_target_unreachable_pass():
    s = _make_scanner()
    with patch.object(s.http, "get", return_value=None):
        results = s.scan(URL)
    assert any(r["status"] == "PASS" for r in results)


def test_github_actions_workflow_fail():
    s = _make_scanner()
    workflow_body = """
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: echo "Building..."
    env:
      NODE_ENV: production
"""

    def se(url, **kw):
        if ".github/workflows" in url:
            return _resp(200, workflow_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("GitHub Actions" in f["type"] or "CI/CD" in f["type"] for f in fails)


def test_hardcoded_secret_in_workflow_fail():
    s = _make_scanner()
    workflow_body = """
name: Deploy
jobs:
  deploy:
    env:
      AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

    def se(url, **kw):
        if ".github/workflows/main.yml" in url:
            return _resp(200, workflow_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("hardcoded secret" in f["type"].lower() for f in fails)


def test_dockerfile_exposed_fail():
    s = _make_scanner()
    dockerfile_body = """
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["gunicorn", "app:app"]
"""

    def se(url, **kw):
        if url.endswith("/Dockerfile"):
            return _resp(200, dockerfile_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("Dockerfile" in f["type"] for f in fails)


def test_docker_compose_fail():
    s = _make_scanner()
    compose_body = """
version: '3'
services:
  web:
    image: myapp:latest
    ports:
      - "80:5000"
  db:
    image: postgres:15
    environment:
      POSTGRES_PASSWORD: mysecretpassword
"""

    def se(url, **kw):
        if "docker-compose.yml" in url:
            return _resp(200, compose_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("docker-compose" in f["type"].lower() or "CI/CD" in f["type"] for f in fails)


def test_travis_ci_exposed_fail():
    s = _make_scanner()
    travis_body = """
language: python
python:
  - "3.11"
script:
  - pytest tests/
deploy:
  provider: heroku
  api_key: $HEROKU_API_KEY
"""

    def se(url, **kw):
        if ".travis.yml" in url:
            return _resp(200, travis_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("Travis" in f["type"] or "CI/CD" in f["type"] for f in fails)


def test_package_json_exposed_warn():
    s = _make_scanner()
    pkg_body = '{"name":"myapp","version":"1.0.0","dependencies":{"express":"^4.18.2"}}'

    def se(url, **kw):
        if url.endswith("/package.json"):
            return _resp(200, pkg_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("package.json" in w["type"] for w in warns)


def test_coverage_report_exposed_warn():
    s = _make_scanner()
    coverage_body = """<?xml version="1.0" ?>
<coverage version="7.4" timestamp="1719000000">
  <packages><package name="tblue.scanner"/></packages>
</coverage>"""

    def se(url, **kw):
        if "coverage.xml" in url:
            return _resp(200, coverage_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    warns = [r for r in results if r["status"] == "WARN"]
    assert any("Coverage" in w["type"] for w in warns)


def test_circleci_with_secret_ref_fail():
    s = _make_scanner()
    circle_body = """
version: 2.1
jobs:
  build:
    docker:
      - image: cimg/python:3.11
    steps:
      - run:
          name: Deploy
          command: |
            echo $CIRCLE_TOKEN
            aws s3 sync . s3://mybucket
    environment:
      AWS_ACCESS_KEY_ID: $CI_AWS_ACCESS_KEY_ID
"""

    def se(url, **kw):
        if ".circleci/config.yml" in url:
            return _resp(200, circle_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("CI/CD" in f["type"] or "CircleCI" in f["type"] for f in fails)


def test_empty_response_body_skipped():
    """Body too short (< 10 chars) should not trigger a finding."""
    s = _make_scanner()

    def se(url, **kw):
        if ".github/workflows" in url:
            return _resp(200, "ok")  # less than 10 chars
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    # Short body skipped → ends up as PASS
    fails = [r for r in results if r["status"] == "FAIL"]
    assert not fails


def test_aws_access_key_in_file_fail():
    """AWS access key pattern in exposed file triggers FAIL."""
    s = _make_scanner()
    jenkins_body = """
pipeline {
    agent any
    environment {
        AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'
        AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    }
}
"""

    def se(url, **kw):
        if "Jenkinsfile" in url:
            return _resp(200, jenkins_body)
        return _resp(404)

    with patch.object(s.http, "get", side_effect=se):
        results = s.scan(URL)
    fails = [r for r in results if r["status"] == "FAIL"]
    assert any("CI/CD" in f["type"] or "Jenkinsfile" in f["type"] for f in fails)
