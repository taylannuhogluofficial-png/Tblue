"""
SBOM (Software Bill of Materials) passive scanner.

Detects exposed package manifests and dependency lockfiles, then builds a
lightweight CycloneDX-compatible SBOM inventory from their contents.
All analysis is passive — no dependency-specific HTTP requests.
"""

import re
import json
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

# Manifest paths to probe
_MANIFEST_PATHS = [
    "/package.json",
    "/package-lock.json",
    "/yarn.lock",
    "/requirements.txt",
    "/Pipfile.lock",
    "/Gemfile.lock",
    "/go.mod",
    "/go.sum",
    "/composer.json",
    "/composer.lock",
    "/pom.xml",
    "/build.gradle",
    "/Cargo.toml",
    "/Cargo.lock",
    "/pyproject.toml",
    "/setup.cfg",
]

_PKG_JSON_DEP_RE    = re.compile(r'"([^"]+)":\s*"([^"]+)"')
_REQUIREMENTS_RE    = re.compile(r'^([A-Za-z0-9_\-\.]+)[>=<!\s]*([0-9][0-9A-Za-z\.\-]*)?\s*$', re.M)
_GEMFILE_GEM_RE     = re.compile(r'^\s*([A-Za-z0-9_\-\.]+)\s+\(([0-9][^\)]*)\)', re.M)
_GO_MOD_RE          = re.compile(r'^\s*([a-z0-9\./\-]+)\s+v([0-9][^\s]*)', re.M | re.I)
_MAVEN_ARTIFACT_RE  = re.compile(
    r'<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>',
    re.S
)

_KNOWN_DEPRECATED: Dict[str, str] = {
    "lodash":       "4.17.21",  # last safe
    "jquery":       "3.7.1",
    "angular":      "1.8.3",
    "moment":       "2.29.4",
    "request":      "deprecated",
    "left-pad":     "deprecated",
    "event-stream": "deprecated",
}


def _parse_pkg_json(content: str) -> List[Dict]:
    comps = []
    try:
        data = json.loads(content)
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for name, version in (data.get(section) or {}).items():
                comps.append({"type": "npm", "name": name, "version": version.lstrip("^~>=")})
    except Exception:
        pass
    return comps


def _parse_requirements(content: str) -> List[Dict]:
    comps = []
    for m in _REQUIREMENTS_RE.finditer(content):
        name, ver = m.group(1), m.group(2) or "unknown"
        if name.startswith("#"):
            continue
        comps.append({"type": "pypi", "name": name, "version": ver})
    return comps


def _parse_gemfile_lock(content: str) -> List[Dict]:
    return [
        {"type": "gem", "name": m.group(1), "version": m.group(2)}
        for m in _GEMFILE_GEM_RE.finditer(content)
    ]


def _parse_go_mod(content: str) -> List[Dict]:
    return [
        {"type": "go", "name": m.group(1), "version": m.group(2)}
        for m in _GO_MOD_RE.finditer(content)
    ]


def _parse_pom(content: str) -> List[Dict]:
    return [
        {"type": "maven",
         "name": f"{m.group(1)}:{m.group(2)}",
         "version": m.group(3)}
        for m in _MAVEN_ARTIFACT_RE.finditer(content)
    ]


def _check_deprecated(comp: Dict) -> Optional[str]:
    name = comp["name"].lower()
    for pattern, last_safe in _KNOWN_DEPRECATED.items():
        if name == pattern:
            if last_safe == "deprecated":
                return f"Package '{comp['name']}' is deprecated/abandoned — find an actively maintained alternative."
            return None
    return None


class SBOMScanner(BaseScanner):
    """SBOM inventory builder from exposed package manifests."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        parsed  = urlparse(url)
        base    = parsed.scheme + "://" + parsed.netloc
        found_components: List[Dict] = []
        found_manifests:  List[str]  = []

        for path in _MANIFEST_PATHS:
            probe_url = base + path
            resp = self.http.get(probe_url)
            if resp is None or resp.status_code not in (200, 206):
                continue
            content = resp.text or ""
            if len(content) < 10:
                continue

            found_manifests.append(path)
            comps: List[Dict] = []

            if path.endswith("package.json") and not path.endswith("package-lock.json"):
                comps = _parse_pkg_json(content)
            elif path in ("/requirements.txt", "/setup.cfg", "/pyproject.toml"):
                comps = _parse_requirements(content)
            elif path.endswith("Gemfile.lock"):
                comps = _parse_gemfile_lock(content)
            elif path in ("/go.mod", "/go.sum"):
                comps = _parse_go_mod(content)
            elif path.endswith("pom.xml"):
                comps = _parse_pom(content)

            if comps:
                found_components.extend(comps)
                self.results.append(self._result(
                    probe_url, "sbom_manifest_exposed", "WARN",
                    detail=f"SBOM: '{path}' is publicly accessible and lists "
                           f"{len(comps)} component(s). Manifests expose your dependency graph to attackers — "
                           "restrict access to /.well-known/security.txt only or deny manifest paths at the CDN/WAF."
                ))
            else:
                # manifest accessible but not parseable (binary lockfile, etc.)
                self.results.append(self._result(
                    probe_url, "sbom_manifest_exposed_unparsed", "WARN",
                    detail=f"SBOM: '{path}' is publicly accessible. Could not parse component list "
                           "(binary or unfamiliar format) — restrict public access."
                ))

        if not found_manifests:
            self.results.append(self._result(
                url, "sbom_no_manifest_exposed", "PASS",
                detail="SBOM: No publicly accessible package manifests found. Good."
            ))
            return self.results

        # Deprecated / abandoned package check
        deprecated_found = []
        for comp in found_components:
            warning = _check_deprecated(comp)
            if warning:
                deprecated_found.append(warning)

        if deprecated_found:
            for msg in deprecated_found[:5]:
                self.results.append(self._result(
                    url, "sbom_deprecated_package", "WARN", detail=msg
                ))

        # Summary finding with full component count
        total = len(found_components)
        unique_types = list({c["type"] for c in found_components})
        self.results.append(self._result(
            url, "sbom_inventory_summary", "WARN",
            detail=f"SBOM Inventory: {total} components identified across "
                   f"{len(found_manifests)} manifest(s). Ecosystem(s): {unique_types}. "
                   "Run SCA (sca scanner) for CVE lookup. Consider generating a formal SBOM "
                   "(CycloneDX / SPDX) as part of your CI/CD pipeline."
        ))

        return self.results
