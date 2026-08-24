"""
Tests for the exposed file scanner.
"""

import pytest
from unittest.mock import MagicMock
from tblue.scanner.exposure import ExposureScanner


def make_scanner(hits: dict = None) -> ExposureScanner:
    """
    hits: {path_suffix: (status_code, body, content_type)}
    Unmatched paths → 404.
    """
    hits    = hits or {}
    session = MagicMock()

    def fake_request(method, url, **kwargs):
        resp = MagicMock()
        for suffix, (code, body, ct) in hits.items():
            if url.endswith(suffix) or suffix in url:
                resp.status_code = code
                resp.text        = body
                resp.headers     = {"content-type": ct}
                resp.url         = url
                return resp
        resp.status_code = 404
        resp.text        = "Not Found"
        resp.headers     = {"content-type": "text/plain"}
        resp.url         = url
        return resp

    session.request.side_effect = fake_request
    return ExposureScanner(session)


_SWAGGER_JSON = '{"swagger":"2.0","info":{"title":"My API","version":"1.0"},"paths":{"/users":{},"components":{}}}'
_OPENAPI_YAML = "openapi: 3.0.0\ninfo:\n  title: My API\n  version: 1.0.0\npaths:\n  /users:\n    get:"
_PACKAGE_JSON = '{"name":"my-app","version":"1.0.0","dependencies":{"express":"^4.18"}}'
_COMPOSE_JSON = '{"name":"my-app","require":{"laravel/framework":"^10.0"}}'
_REQUIREMENTS = "Django==4.2.1\nrequests>=2.28.0\ngunicorn==20.1.0"
_GITLAB_CI    = "stages:\n  - build\n  - deploy\nbuild:\n  script:\n    - npm run build"


# ── API spec exposure ─────────────────────────────────────────────────────────

def test_swagger_json_exposed_fails():
    scanner = make_scanner({"/swagger.json": (200, _SWAGGER_JSON, "application/json")})
    results = scanner.scan("https://example.com")
    assert any("swagger" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_openapi_yaml_exposed_fails():
    scanner = make_scanner({"/openapi.yaml": (200, _OPENAPI_YAML, "text/yaml")})
    results = scanner.scan("https://example.com")
    assert any("openapi" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_api_docs_exposed_fails():
    scanner = make_scanner({"/api-docs": (200, _SWAGGER_JSON, "application/json")})
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "FAIL" for r in results)


# ── Dependency manifest exposure ──────────────────────────────────────────────

def test_package_json_exposed_warns():
    scanner = make_scanner({"/package.json": (200, _PACKAGE_JSON, "application/json")})
    results = scanner.scan("https://example.com")
    assert any("package.json" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_composer_json_exposed_warns():
    scanner = make_scanner({"/composer.json": (200, _COMPOSE_JSON, "application/json")})
    results = scanner.scan("https://example.com")
    assert any("composer" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_requirements_txt_exposed_warns():
    scanner = make_scanner({"/requirements.txt": (200, _REQUIREMENTS, "text/plain")})
    results = scanner.scan("https://example.com")
    assert any("requirements.txt" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── CI/CD config exposure ─────────────────────────────────────────────────────

def test_gitlab_ci_exposed_warns():
    scanner = make_scanner({"/.gitlab-ci.yml": (200, _GITLAB_CI, "text/yaml")})
    results = scanner.scan("https://example.com")
    assert any("gitlab" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── HTML false positive avoidance ─────────────────────────────────────────────

def test_html_response_not_flagged():
    html = "<html><body><h1>Not Found</h1></body></html>"
    scanner = make_scanner({"/swagger.json": (200, html, "text/html")})
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] == "FAIL" for r in results)


# ── Clean — nothing exposed ───────────────────────────────────────────────────

def test_nothing_exposed_passes():
    scanner = make_scanner()  # all 404
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)
    assert not any(r["status"] in ("FAIL", "WARN") for r in results)


# ── Detail quality ────────────────────────────────────────────────────────────

def test_exposed_result_has_fix_guidance():
    scanner = make_scanner({"/swagger.json": (200, _SWAGGER_JSON, "application/json")})
    results = scanner.scan("https://example.com")
    fails   = [r for r in results if r["status"] == "FAIL"]
    assert any("fix" in r["detail"].lower() for r in fails)


# ── API spec validation (thin content rejected) ──────────────────────────────

def test_minimal_json_not_flagged_as_api_spec():
    # Returns 200 JSON but doesn't look like an API spec
    scanner = make_scanner({"/swagger.json": (200, '{"hello":"world"}', "application/json")})
    results = scanner.scan("https://example.com")
    assert not any("swagger" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_swagger_ui_html_detected():
    html = '<html><body><div id="swagger-ui">swagger</div></body></html>'
    scanner = make_scanner({"/swagger/index.html": (200, html, "text/html")})
    # Swagger UI HTML is html content — should be filtered by _is_html
    # so this should NOT produce a FAIL (it IS html)
    results = scanner.scan("https://example.com")
    # verify scan runs without error
    assert isinstance(results, list)


# ── Dependency manifest detection ─────────────────────────────────────────────

def test_go_mod_exposed_warns():
    body = "module github.com/example/myapp\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.1\n)"
    scanner = make_scanner({"/go.mod": (200, body, "text/plain")})
    results = scanner.scan("https://example.com")
    assert any("go.mod" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_gemfile_exposed_warns():
    body = "source 'https://rubygems.org'\ngem 'rails', '~> 7.0'\ngem 'pg'"
    scanner = make_scanner({"/Gemfile": (200, body, "text/plain")})
    results = scanner.scan("https://example.com")
    assert any("gemfile" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_pipfile_exposed_warns():
    body = "[packages]\nrequests = \">=2.28\"\nDjango = \"==4.2\""
    scanner = make_scanner({"/Pipfile": (200, body, "text/plain")})
    results = scanner.scan("https://example.com")
    assert any("pipfile" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── CI/CD pipeline files ──────────────────────────────────────────────────────

def test_github_actions_exposed_warns():
    body = "name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest"
    scanner = make_scanner({"/.github/workflows/ci.yml": (200, body, "text/yaml")})
    results = scanner.scan("https://example.com")
    assert any("github actions" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_jenkinsfile_exposed_warns():
    body = "pipeline {\n  agent any\n  stages { stage('Build') { steps { sh 'make' } } }\n}"
    scanner = make_scanner({"/Jenkinsfile": (200, body, "text/plain")})
    results = scanner.scan("https://example.com")
    assert any("jenkinsfile" in r["type"].lower() and r["status"] == "WARN" for r in results)


# ── 206 partial content accepted ─────────────────────────────────────────────

def test_206_partial_content_accepted():
    scanner = make_scanner({"/swagger.json": (206, _SWAGGER_JSON, "application/json")})
    results = scanner.scan("https://example.com")
    assert any("swagger" in r["type"].lower() and r["status"] == "FAIL" for r in results)


# ── None / redirect responses ─────────────────────────────────────────────────

def test_301_redirect_not_flagged():
    scanner = make_scanner({"/swagger.json": (301, "", "text/html")})
    results = scanner.scan("https://example.com")
    assert not any("swagger" in r["type"].lower() and r["status"] == "FAIL" for r in results)


# ── Coverage gap tests ────────────────────────────────────────────────────────

def test_dep_file_body_fails_validation_skipped():
    """requirements.txt body has no version specifiers → _looks_like_dep_file False → continue line 127."""
    body = "just some plain text without version specifiers here"
    scanner = make_scanner({"/requirements.txt": (200, body, "text/plain")})
    results = scanner.scan("https://example.com")
    assert any(r["status"] == "PASS" for r in results)
    assert not any("requirements" in r["type"].lower() for r in results)


def test_swagger_ui_html_path_plain_text_body():
    """swagger-ui.html with plain-text body containing 'swagger' → line 163 in _looks_like_api_spec."""
    body = "swagger openapi documentation page"
    scanner = make_scanner({"/swagger-ui.html": (200, body, "text/plain")})
    results = scanner.scan("https://example.com")
    assert any("swagger" in r["type"].lower() and r["status"] == "FAIL" for r in results)


def test_pom_xml_exposed_warns():
    """pom.xml returns 200 with XML body → _looks_like_dep_file line 181 → WARN."""
    body = "<project>\n  <groupId>com.example</groupId>\n  <artifactId>app</artifactId>\n</project>"
    scanner = make_scanner({"/pom.xml": (200, body, "application/xml")})
    results = scanner.scan("https://example.com")
    assert any("pom" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_cargo_toml_exposed_warns():
    """Cargo.toml returns 200 → _looks_like_dep_file lines 184-185 → WARN."""
    body = "[package]\nname = \"my-crate\"\nversion = \"0.1.0\"\n[dependencies]\ntokio = \"1.0\""
    scanner = make_scanner({"/Cargo.toml": (200, body, "text/plain")})
    results = scanner.scan("https://example.com")
    assert any("cargo" in r["type"].lower() and r["status"] == "WARN" for r in results)


def test_build_gradle_exposed_warns():
    """build.gradle returns 200 → _looks_like_dep_file fallback return True line 186 → WARN."""
    body = "apply plugin: 'java'\ndependencies { implementation 'org.springframework:spring-core:5.3' }"
    scanner = make_scanner({"/build.gradle": (200, body, "text/plain")})
    results = scanner.scan("https://example.com")
    assert any("gradle" in r["type"].lower() and r["status"] == "WARN" for r in results)
