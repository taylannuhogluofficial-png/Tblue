"""
CI/CD Pipeline Configuration Exposure Scanner.

Publicly accessible CI/CD configuration files are a critical blue-team
finding: they expose secrets, credentials, environment variables, and
internal infrastructure details to unauthenticated attackers.

Detection approach (read-only GET probes):
1. Probe well-known CI/CD config paths (.github, .gitlab-ci.yml, Jenkinsfile,
   Dockerfile, docker-compose.yml, .travis.yml, etc.)
2. For accessible files, scan content for hardcoded secrets patterns
3. Detect secret references: ${{ secrets.X }}, env: KEY=VALUE, AWS keys, tokens
4. Check for exposed build artifacts (coverage reports, test results) in common paths
5. Flag Docker image names that reveal internal registry addresses

Professional equivalent: Burp Suite Pro "interesting file" scan policy,
Detectify CI/CD exposure checks, GitLeaks patterns.

CWE-312: Cleartext Storage of Sensitive Information
CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
"""

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# CI/CD config files to probe — (path, label, severity, reason)
_CICD_PATHS: List[Tuple[str, str, str, str]] = [
    # GitHub Actions
    ("/.github/workflows/",         "GitHub Actions workflows dir",    "FAIL",
     "GitHub Actions workflow YAML files may contain hardcoded secrets, token grants, and internal infrastructure paths."),
    ("/.github/workflows/main.yml", "GitHub Actions main workflow",    "FAIL",
     "GitHub workflow file may expose secrets references, environment variable names, and deployment targets."),
    ("/.github/workflows/ci.yml",   "GitHub Actions CI workflow",      "FAIL",
     "CI workflow may expose secrets, build commands, and environment structure."),
    ("/.github/workflows/deploy.yml","GitHub Actions deploy workflow", "FAIL",
     "Deployment workflow may expose cloud credentials, registry endpoints, and deploy keys."),

    # GitLab CI
    ("/.gitlab-ci.yml",             "GitLab CI configuration",        "FAIL",
     "GitLab CI config may expose protected variable names, runner tags, and deployment scripts."),

    # Jenkins
    ("/Jenkinsfile",                 "Jenkinsfile",                    "FAIL",
     "Jenkinsfile exposes pipeline stages, credential IDs, agent labels, and internal tool paths."),
    ("/jenkins/job/",               "Jenkins job directory",          "WARN",
     "Exposed Jenkins job listing reveals pipeline names and build history."),

    # Travis CI
    ("/.travis.yml",                "Travis CI config",               "FAIL",
     "Travis config may expose encrypted secret names, deployment targets, and environment variables."),

    # CircleCI
    ("/.circleci/config.yml",       "CircleCI configuration",         "FAIL",
     "CircleCI config exposes orbs, context names, job structure, and environment variable names."),

    # Drone CI
    ("/.drone.yml",                 "Drone CI configuration",         "FAIL",
     "Drone CI config may expose pipeline steps, secret references, and internal registry paths."),

    # Azure DevOps / Bitbucket Pipelines / Others
    ("/azure-pipelines.yml",        "Azure Pipelines config",         "FAIL",
     "Azure Pipelines YAML may expose variable group names, service connection IDs, and agent pool names."),
    ("/bitbucket-pipelines.yml",    "Bitbucket Pipelines config",     "FAIL",
     "Bitbucket Pipelines config may expose deployment environment names and secret variable keys."),
    ("/Makefile",                   "Makefile",                       "WARN",
     "Exposed Makefile reveals build targets, toolchain paths, and may include hardcoded configuration."),

    # Docker
    ("/Dockerfile",                 "Dockerfile",                     "FAIL",
     "Dockerfile may expose base image registry, build args, installed software versions, and internal paths."),
    ("/docker-compose.yml",         "docker-compose.yml",             "FAIL",
     "docker-compose exposes service topology, port mappings, volume mounts, and environment variables."),
    ("/docker-compose.yaml",        "docker-compose.yaml",            "FAIL",
     "docker-compose exposes service topology, port mappings, and potentially hardcoded secrets."),
    ("/.dockerignore",              ".dockerignore",                  "WARN",
     "Exposed .dockerignore reveals which files exist in the build context."),

    # Build artifacts / coverage / test results
    ("/coverage/",                  "Coverage report directory",      "WARN",
     "Exposed coverage reports reveal internal code paths, class names, and test coverage gaps."),
    ("/coverage.xml",               "Coverage XML report",            "WARN",
     "Coverage XML contains source file paths and package names."),
    ("/test-results/",              "Test results directory",         "WARN",
     "Exposed test results may reveal internal module names and failure patterns."),
    ("/build/reports/",             "Build reports directory",        "WARN",
     "Gradle/Maven build reports expose dependency versions and audit results."),

    # Package/dependency files
    ("/package.json",               "package.json",                   "WARN",
     "package.json reveals dependency list, version ranges, scripts, and may contain registry auth config."),
    ("/composer.json",              "composer.json",                  "WARN",
     "Composer config reveals PHP dependency tree and may expose private package repository URLs."),
    ("/requirements.txt",           "requirements.txt",               "WARN",
     "Python requirements file reveals dependency names and versions for fingerprinting."),
    ("/go.sum",                     "go.sum",                         "WARN",
     "Go module checksum file exposes full dependency tree and versions."),
    ("/Gemfile",                    "Gemfile",                        "WARN",
     "Ruby Gemfile reveals dependency structure and may expose private gem source URLs."),
]

# Patterns indicating hardcoded secrets in exposed config files
_SECRET_RE = re.compile(
    r"""
    (?:
        [A-Z_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY|
                  AUTH_KEY|CREDENTIALS|DATABASE_URL|DB_PASS)[A-Z_]*
        \s*[=:]\s*
        ["']?[A-Za-z0-9+/=_\-]{12,}["']?   # actual value (not placeholder)
    ) |
    (?:AKIA[0-9A-Z]{16}) |                  # AWS access key ID
    (?:sk_live_[A-Za-z0-9]{24}) |           # Stripe live key
    (?:ghp_[A-Za-z0-9]{36}) |              # GitHub personal access token
    (?:xox[bpars]-[0-9]{10,13}-[0-9]{10,13}) # Slack tokens
    """,
    re.I | re.X,
)

# GitHub Actions / GitLab secret variable references (not hardcoded but info-leaking)
_SECRET_REF_RE = re.compile(
    r"""
    \$\{\{\s*secrets\.[A-Z_]+\s*\}\} |   # ${{ secrets.AWS_KEY }}
    \$CI_[A-Z_]+_TOKEN |                   # GitLab CI token vars
    \$GITHUB_TOKEN |
    \$TRAVIS_[A-Z_]+ |
    secretKeyRef:|                          # k8s secret ref
    valueFrom:\s*\n\s+secretKeyRef
    """,
    re.I | re.X,
)

# Internal registry / infrastructure markers
_INTERNAL_INFRA_RE = re.compile(
    r"""
    (?:registry|docker|artifactory|nexus|harbor)\.[a-z0-9\-]+\.(?:internal|corp|local|lan) |
    \b10\.\d+\.\d+\.\d+:\d{2,5}/ |         # private registry IP:port/
    (?:ssh|git)@[a-z0-9\-]+\.(?:internal|corp|local)
    """,
    re.I | re.X,
)


class CICDExposureScanner(BaseScanner):
    """Detect publicly accessible CI/CD configuration files that may expose secrets."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "CI/CD exposure — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        found_any = False

        for path, label, severity, reason in _CICD_PATHS:
            probe_url = urljoin(base + "/", path.lstrip("/"))
            try:
                r = self.http.get(probe_url)
                if not r or r.status_code not in (200, 206):
                    continue

                body = r.text or ""
                if len(body) < 10:
                    continue

                found_any = True

                # Scan content for secrets / secret references / internal infra
                secret_match = _SECRET_RE.search(body)
                secret_ref_match = _SECRET_REF_RE.search(body)
                internal_match = _INTERNAL_INFRA_RE.search(body)

                if secret_match:
                    snippet = secret_match.group(0)[:60]
                    log_fail(logger, f"Hardcoded secret in {probe_url}: {snippet}")
                    self.results.append(self._result(
                        probe_url,
                        f"CI/CD exposure — hardcoded secret in {label}",
                        "FAIL",
                        detail=(
                            f"{label} is publicly accessible at {probe_url} "
                            f"and contains a potential hardcoded secret: '{snippet}'. "
                            f"{reason} "
                            "Fix: remove all secrets from CI/CD config files; "
                            "use secret management systems (GitHub Secrets, HashiCorp Vault, "
                            "AWS Secrets Manager); restrict access to CI/CD files via .htaccess "
                            "or web server configuration."
                        )
                    ))
                elif severity == "FAIL":
                    extra = ""
                    if secret_ref_match:
                        extra = f" Secret variable references detected: '{secret_ref_match.group(0)[:50]}'."
                    elif internal_match:
                        extra = f" Internal infrastructure reference found: '{internal_match.group(0)[:50]}'."
                    log_fail(logger, f"CI/CD config exposed: {probe_url}")
                    self.results.append(self._result(
                        probe_url,
                        f"CI/CD exposure — {label} publicly accessible",
                        "FAIL",
                        detail=(
                            f"{label} is publicly accessible at {probe_url}.{extra} "
                            f"{reason} "
                            "Fix: block access to CI/CD configuration files via web server "
                            "rules (nginx location ~* /\\.github deny all; Apache deny from all); "
                            "move CI files above the web root; review for committed secrets."
                        )
                    ))
                else:
                    log_warn(logger, f"Build artifact/config exposed: {probe_url}")
                    self.results.append(self._result(
                        probe_url,
                        f"CI/CD exposure — {label} accessible",
                        "WARN",
                        detail=(
                            f"{label} is accessible at {probe_url}. "
                            f"{reason} "
                            "Verify this file does not need to be publicly accessible; "
                            "restrict access if not required."
                        )
                    ))

            except Exception:
                continue

        if not found_any:
            log_pass(logger, f"No CI/CD configuration files exposed on {url}")
            self.results.append(self._result(
                url,
                "CI/CD exposure — no pipeline configuration files exposed",
                "PASS",
                detail=(
                    "No publicly accessible CI/CD configuration files found. "
                    "Checked: GitHub Actions, GitLab CI, Jenkins, Travis CI, CircleCI, "
                    "Drone, Azure Pipelines, Dockerfile, docker-compose, and build artifacts."
                )
            ))

        return self.results
