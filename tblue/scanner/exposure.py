"""
Exposed file scanner.

Probes for three categories of unintentionally public files:

1. API specification files (OpenAPI/Swagger) — hands attackers a full API map
2. Dependency manifests (package.json, composer.json, requirements.txt, etc.)
   — reveals exact library versions for CVE targeting
3. CI/CD pipeline configs (.github/workflows/, .gitlab-ci.yml, Jenkinsfile, etc.)
   — exposes build/deploy secrets, environment variable names, infrastructure details
"""

from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# (path, label, category, status_on_hit)
_PROBES: List[Tuple[str, str, str, str]] = [
    # ── OpenAPI / Swagger ──────────────────────────────────────────────────
    ("/swagger.json",           "Swagger JSON",              "api_spec", "FAIL"),
    ("/swagger.yaml",           "Swagger YAML",              "api_spec", "FAIL"),
    ("/openapi.json",           "OpenAPI JSON",              "api_spec", "FAIL"),
    ("/openapi.yaml",           "OpenAPI YAML",              "api_spec", "FAIL"),
    ("/api-docs",               "API docs (generic)",        "api_spec", "FAIL"),
    ("/api-docs.json",          "API docs JSON",             "api_spec", "FAIL"),
    ("/v1/api-docs",            "API docs v1",               "api_spec", "FAIL"),
    ("/v2/api-docs",            "API docs v2",               "api_spec", "FAIL"),
    ("/v3/api-docs",            "API docs v3",               "api_spec", "FAIL"),
    ("/swagger/index.html",     "Swagger UI",                "api_spec", "FAIL"),
    ("/swagger-ui.html",        "Swagger UI (legacy)",       "api_spec", "FAIL"),
    ("/api/swagger.json",       "API Swagger JSON",          "api_spec", "FAIL"),
    ("/api/swagger.yaml",       "API Swagger YAML",          "api_spec", "FAIL"),
    ("/spec/swagger.json",      "Spec Swagger JSON",         "api_spec", "FAIL"),

    # ── Dependency manifests ───────────────────────────────────────────────
    ("/package.json",           "package.json",              "dep_file", "WARN"),
    ("/package-lock.json",      "package-lock.json",         "dep_file", "WARN"),
    ("/yarn.lock",              "yarn.lock",                 "dep_file", "WARN"),
    ("/composer.json",          "composer.json",             "dep_file", "WARN"),
    ("/composer.lock",          "composer.lock",             "dep_file", "WARN"),
    ("/requirements.txt",       "requirements.txt",          "dep_file", "WARN"),
    ("/Pipfile",                "Pipfile",                   "dep_file", "WARN"),
    ("/Pipfile.lock",           "Pipfile.lock",              "dep_file", "WARN"),
    ("/Gemfile",                "Gemfile",                   "dep_file", "WARN"),
    ("/Gemfile.lock",           "Gemfile.lock",              "dep_file", "WARN"),
    ("/go.mod",                 "go.mod",                    "dep_file", "WARN"),
    ("/go.sum",                 "go.sum",                    "dep_file", "WARN"),
    ("/pom.xml",                "pom.xml (Maven)",           "dep_file", "WARN"),
    ("/build.gradle",           "build.gradle (Gradle)",     "dep_file", "WARN"),
    ("/Cargo.toml",             "Cargo.toml (Rust)",         "dep_file", "WARN"),

    # ── CI/CD pipeline configs ─────────────────────────────────────────────
    ("/.github/workflows/ci.yml",       "GitHub Actions CI",     "cicd", "WARN"),
    ("/.github/workflows/main.yml",     "GitHub Actions main",   "cicd", "WARN"),
    ("/.github/workflows/deploy.yml",   "GitHub Actions deploy", "cicd", "WARN"),
    ("/.gitlab-ci.yml",                 ".gitlab-ci.yml",        "cicd", "WARN"),
    ("/Jenkinsfile",                     "Jenkinsfile",           "cicd", "WARN"),
    ("/.travis.yml",                     ".travis.yml",           "cicd", "WARN"),
    ("/.circleci/config.yml",            "CircleCI config",       "cicd", "WARN"),
    ("/azure-pipelines.yml",             "Azure Pipelines",       "cicd", "WARN"),
    ("/.drone.yml",                      ".drone.yml",            "cicd", "WARN"),
    ("/bitbucket-pipelines.yml",         "Bitbucket Pipelines",   "cicd", "WARN"),
    ("/buildspec.yml",                   "AWS CodeBuild spec",    "cicd", "WARN"),
    ("/cloudbuild.yaml",                 "GCP Cloud Build",       "cicd", "WARN"),
]

_CATEGORY_LABELS = {
    "api_spec": "API specification",
    "dep_file": "dependency manifest",
    "cicd":     "CI/CD pipeline config",
}

_CATEGORY_DETAIL = {
    "api_spec": (
        "An OpenAPI/Swagger specification file is publicly accessible. "
        "This hands any visitor a complete map of your API: all endpoints, "
        "parameters, authentication schemes, and data models. "
        "Attackers use this to find undocumented routes and craft targeted attacks. "
        "Fix: require authentication to access API docs, or remove them from production entirely. "
        "In Swagger UI: set url to require auth. In Spring Boot: disable springfox in prod profile."
    ),
    "dep_file": (
        "A dependency manifest is publicly accessible from the web root. "
        "This reveals exact library names and versions, allowing attackers to search "
        "for known CVEs in your specific dependency tree. "
        "Fix: ensure your web server root (public/, dist/, www/) does not include project "
        "root files. Add the filename to .gitignore for web roots if using static hosting."
    ),
    "cicd": (
        "A CI/CD pipeline configuration file is accessible from the web. "
        "These files often contain environment variable names, deployment targets, "
        "secret references, and infrastructure details. "
        "Fix: ensure your CI/CD config files are not in the web-accessible document root. "
        "They belong in the project root, not in public/, dist/, or www/."
    ),
}


class ExposureScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        found: Dict[str, List[str]] = {"api_spec": [], "dep_file": [], "cicd": []}

        for path, label, category, status in _PROBES:
            probe_url = urljoin(base, path)
            resp = self.http.get(probe_url, allow_redirects=False)
            if not resp or resp.status_code not in (200, 206):
                continue

            body = resp.text or ""
            # Skip HTML responses (custom 404 pages returning 200)
            if _is_html(body, resp.headers.get("content-type", "")):
                continue

            # Minimal content validation per category
            if category == "api_spec" and not _looks_like_api_spec(body, path):
                continue
            if category == "dep_file" and not _looks_like_dep_file(body, path):
                continue

            found[category].append(label)
            log_fail(logger, f"Exposed {_CATEGORY_LABELS[category]}: {probe_url}") \
                if status == "FAIL" else \
                log_warn(logger, f"Exposed {_CATEGORY_LABELS[category]}: {probe_url}")

            self.results.append(self._result(
                probe_url,
                f"Exposed file — {label}",
                status,
                detail=(
                    f"{label} is publicly accessible at {probe_url}. "
                    + _CATEGORY_DETAIL[category]
                )
            ))

        if not any(found.values()):
            log_pass(logger, f"No exposed specs, manifests, or CI/CD configs — {url}")
            self.results.append(self._result(
                url, "Exposed files — none found", "PASS",
                detail="No API specs, dependency manifests, or CI/CD configs found in the web root."
            ))

        return self.results


def _is_html(body: str, content_type: str) -> bool:
    if "text/html" in content_type:
        return True
    stripped = body.lstrip()
    return stripped.startswith("<!") or stripped.lower().startswith("<html")


def _looks_like_api_spec(body: str, path: str) -> bool:
    if path.endswith(".html"):
        return "swagger" in body.lower() or "openapi" in body.lower()
    markers = ("swagger", "openapi", "paths", "components", "info", "version")
    return sum(1 for m in markers if m in body.lower()) >= 2


def _looks_like_dep_file(body: str, path: str) -> bool:
    name = path.lower().split("/")[-1]
    if "package" in name:
        return '"dependencies"' in body or '"name"' in body
    if "composer" in name:
        return '"require"' in body or '"name"' in body
    if "requirements" in name:
        return any(c in body for c in ("==", ">=", "<=", "~="))
    if "gemfile" in name:
        return "gem " in body.lower()
    if name in ("go.mod", "go.sum"):
        return "module " in body or "require " in body
    if "pom.xml" in name:
        return "<project" in body.lower() or "<dependencies" in body.lower()
    if "pipfile" in name:
        return "[packages]" in body or "[dev-packages]" in body
    if "cargo" in name:
        return "[package]" in body or "[dependencies]" in body
    return True
