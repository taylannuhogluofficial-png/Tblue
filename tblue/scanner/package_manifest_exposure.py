"""
Package Manifest Exposure Scanner.

Exposed dependency manifest files reveal exact package versions, enabling
attackers to identify and exploit known vulnerabilities in dependencies.

Files checked:
- package.json / package-lock.json (Node.js)
- yarn.lock (Yarn)
- composer.json / composer.lock (PHP)
- requirements.txt / Pipfile / Pipfile.lock / pyproject.toml (Python)
- Gemfile / Gemfile.lock (Ruby)
- go.mod / go.sum (Go)
- pom.xml (Maven/Java)
- build.gradle (Gradle/Android)
- Cargo.toml / Cargo.lock (Rust)
- .npmrc (npm config — may contain auth tokens)
- .yarnrc / .yarnrc.yml (Yarn config)

Security implications:
1. Exact dependency versions → targeted CVE exploitation
2. Transitive dependency list → supply chain attack surface
3. .npmrc with authToken → publish malicious packages to private registry
4. Scripts section in package.json → reveals build process and CI hooks
5. Private registry URLs → internal infrastructure disclosure
6. Dev dependencies in production → unnecessary attack surface

CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
CWE-1104: Use of Unmaintained Third Party Components
"""

import json
import re
from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_MANIFEST_PATHS = [
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "composer.json",
    "composer.lock",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "pyproject.toml",
    "Gemfile",
    "Gemfile.lock",
    "go.mod",
    "go.sum",
    "pom.xml",
    "build.gradle",
    "Cargo.toml",
    "Cargo.lock",
    ".npmrc",
    ".yarnrc",
    ".yarnrc.yml",
]

_AUTH_TOKEN_RE = re.compile(r'(?:authToken|_authToken|npm_token|//[^/]+/:_authToken)\s*=\s*\S+', re.I)
_PRIVATE_REGISTRY_RE = re.compile(r'https?://(?!registry\.npmjs\.org|registry\.yarnpkg\.com|pypi\.org|rubygems\.org|pkg\.go\.dev|crates\.io)[^\s"\',]+/(?:npm|pypi|maven|rubygems)', re.I)

_KNOWN_SENSITIVE_KEYS_RE = re.compile(
    r'"(?:_password|_authToken|token|secret|password|key|apiKey|auth)\s*"\s*:\s*"[^"]{4,}"',
    re.I
)


def _is_manifest_content(body: str, path: str) -> bool:
    if not body or len(body) < 5:
        return False
    if "package.json" in path:
        return '"name"' in body or '"dependencies"' in body or '"version"' in body
    if "requirements.txt" in path:
        return bool(re.search(r'^\w[\w\-\.]+\s*[=~!<>]', body, re.M))
    if "composer.json" in path:
        return '"require"' in body or '"name"' in body
    if "Gemfile" in path and "Gemfile.lock" not in path:
        return "source " in body or "gem " in body
    if "go.mod" in path:
        return body.startswith("module ")
    if "pom.xml" in path:
        return "<project" in body
    if ".npmrc" in path:
        return "=" in body
    return True


class PackageManifestExposureScanner(BaseScanner):
    """Detect exposed dependency manifest files."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0
        found_any = False

        from urllib.parse import urlparse
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        for path in _MANIFEST_PATHS:
            if findings >= 10:
                break
            probe_url = base + "/" + path
            try:
                resp = self.http.get(probe_url)
            except Exception:
                continue
            if resp is None or resp.status_code != 200:
                continue

            body = resp.text or ""
            if not _is_manifest_content(body, path):
                continue

            found_any = True

            # Determine severity by content
            severity = "WARN"
            extra = ""

            # .npmrc with auth token = FAIL
            if ".npmrc" in path or ".yarnrc" in path:
                if _AUTH_TOKEN_RE.search(body):
                    severity = "FAIL"
                    extra = " (contains authentication token)"
                else:
                    severity = "WARN"
                    extra = " (contains npm/yarn configuration)"
            elif _AUTH_TOKEN_RE.search(body):
                severity = "FAIL"
                extra = " (contains authentication token)"
            elif _KNOWN_SENSITIVE_KEYS_RE.search(body):
                severity = "FAIL"
                extra = " (contains embedded secrets)"
            elif _PRIVATE_REGISTRY_RE.search(body):
                extra = " (references private registry)"

            # Count dependencies if JSON
            dep_count = ""
            if path.endswith(".json") and not path.endswith("-lock.json"):
                try:
                    data = json.loads(body)
                    deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                    if deps:
                        dep_count = f" ({len(deps)} dependencies exposed)"
                except (json.JSONDecodeError, AttributeError):
                    pass

            if severity == "FAIL":
                log_fail(logger, f"Exposed manifest with secrets at {probe_url}")
            else:
                log_warn(logger, f"Exposed package manifest at {probe_url}")

            self.results.append(self._result(
                url,
                f"Package manifest exposure — {path} accessible{extra}{dep_count}",
                severity,
                detail=(
                    f"'{path}' is accessible at '{probe_url}' (HTTP 200). "
                    f"Exposed manifests reveal exact dependency versions, private registry URLs, "
                    f"and build configuration{extra}. "
                    "Attackers use dependency versions to identify known CVEs for targeted exploitation. "
                    "Fix: block access to dependency files via web server config "
                    "(nginx: location ~ /\\.(json|lock|toml|mod|gradle)$ { deny all; }); "
                    "serve only compiled assets from the web root."
                )
            ))
            findings += 1

        if not found_any:
            log_pass(logger, f"No exposed package manifests at {url}")
            self.results.append(self._result(
                url, "Package manifest exposure — no manifest files accessible", "PASS",
                detail="No dependency manifest files found at common paths."
            ))

        return self.results
