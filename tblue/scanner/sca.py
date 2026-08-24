"""
Software Composition Analysis (SCA) via OSV.dev.

If a package manifest (package.json, requirements.txt, Gemfile.lock, etc.)
was found exposed by the exposure scanner, fetches and parses it, then
queries the completely free OSV.dev API (no key needed) to find known CVEs
for each dependency.
"""

import re
import json
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_OSV_QUERY_URL  = "https://api.osv.dev/v1/query"
_OSV_BATCH_URL  = "https://api.osv.dev/v1/querybatch"
_MAX_DEPS       = 50   # cap to avoid very long scan times
_OSV_TIMEOUT    = 20


# Ecosystem mapping
_MANIFEST_ECOSYSTEM: Dict[str, str] = {
    "package.json":    "npm",
    "requirements.txt": "PyPI",
    "gemfile.lock":    "RubyGems",
    "composer.json":   "Packagist",
    "pom.xml":         "Maven",
    "build.gradle":    "Maven",
    "go.sum":          "Go",
    "cargo.lock":      "crates.io",
}

# Known exposed manifest paths we look for
_MANIFEST_PATHS = [
    "/package.json",
    "/requirements.txt",
    "/Gemfile.lock",
    "/composer.json",
    "/pom.xml",
]


def _parse_package_json(content: str) -> List[Tuple[str, str]]:
    try:
        data = json.loads(content)
        deps = {}
        deps.update(data.get("dependencies", {}))
        deps.update(data.get("devDependencies", {}))
        result = []
        for name, ver in deps.items():
            ver = re.sub(r"[^0-9.]", "", ver)
            if ver:
                result.append((name, ver))
        return result
    except Exception:
        return []


def _parse_requirements_txt(content: str) -> List[Tuple[str, str]]:
    deps = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9_.-]+)[=><!\s]+([0-9][0-9a-zA-Z._-]*)", line)
        if m:
            deps.append((m.group(1), m.group(2)))
    return deps


def _parse_gemfile_lock(content: str) -> List[Tuple[str, str]]:
    deps = []
    in_specs = False
    for line in content.splitlines():
        if "GEM" in line or "specs:" in line:
            in_specs = True
            continue
        if in_specs:
            m = re.match(r"^\s{4}([a-zA-Z0-9_-]+)\s+\(([0-9][^\)]*)\)", line)
            if m:
                deps.append((m.group(1), m.group(2)))
            elif line.strip() == "":
                in_specs = False
    return deps


_PARSERS: Dict[str, Any] = {
    "package.json":     _parse_package_json,
    "requirements.txt": _parse_requirements_txt,
    "gemfile.lock":     _parse_gemfile_lock,
}


class SCAScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        # Try each known manifest path
        for path in _MANIFEST_PATHS:
            manifest_url = _build_url(url, path)
            try:
                resp = self.http.get(manifest_url)
                if not resp or resp.status_code != 200:
                    continue
                content = resp.text
                if len(content) < 10 or content.strip().startswith("<"):
                    continue  # HTML false positive
                filename = path.lstrip("/").lower()
                self._analyse_manifest(filename, content, manifest_url)
            except Exception:
                continue
        return self.results

    def scan_manifest(self, filename: str, content: str, source_url: str) -> List[Dict[str, Any]]:
        """Called externally with already-fetched manifest content."""
        self.results = []
        self._analyse_manifest(filename.lower(), content, source_url)
        return self.results

    def _analyse_manifest(self, filename: str, content: str, source_url: str) -> None:
        parser    = _get_parser(filename)
        ecosystem = _get_ecosystem(filename)
        if not parser or not ecosystem:
            return

        deps = parser(content)[:_MAX_DEPS]
        if not deps:
            return

        logger.info(f"SCA: querying OSV for {len(deps)} packages from {source_url}")
        vulns = self._query_osv_batch(deps, ecosystem)

        vulnerable = []
        for name, version, advisories in vulns:
            for adv in advisories:
                adv_id   = adv.get("id", "unknown")
                summary  = adv.get("summary", "")
                severity = _osv_severity(adv)
                vulnerable.append((name, version, adv_id, summary, severity))

        if vulnerable:
            examples = "; ".join(
                f"{n}@{v} ({adv_id})" for n, v, adv_id, _, _ in vulnerable[:5]
            )
            more = f" (+ {len(vulnerable) - 5} more)" if len(vulnerable) > 5 else ""
            highest = _highest_severity([sev for _, _, _, _, sev in vulnerable])
            status  = "FAIL" if highest in ("CRITICAL", "HIGH") else "WARN"
            log_fail(logger, f"SCA: {len(vulnerable)} vulnerable dependencies in {filename}")
            self.results.append(self._result(source_url,
                f"SCA — vulnerable dependencies in {filename}",
                status,
                detail=(
                    f"OSV.dev found {len(vulnerable)} known vulnerabilit(y/ies) in "
                    f"dependencies from exposed {filename}: {examples}{more}. "
                    f"Fix: (1) Remove the exposed {filename} immediately — it should not be "
                    "publicly accessible. (2) Update affected packages. Run 'npm audit fix', "
                    "'pip-audit', or 'bundle audit' to get remediation commands."
                ),
                extra={"sca_findings": [
                    {"package": n, "version": v, "advisory": a, "summary": s, "severity": sev}
                    for n, v, a, s, sev in vulnerable
                ]}
            ))
        else:
            log_pass(logger, f"SCA: no known vulnerabilities found in {filename}")
            self.results.append(self._result(source_url,
                f"SCA — no known vulnerabilities in {filename}",
                "PASS",
                detail=f"Queried {len(deps)} packages from {filename} against OSV.dev — "
                       "no known CVEs found. Note: remove this file from public access regardless."))

    def _query_osv_batch(self, deps: List[Tuple[str, str]], ecosystem: str) -> List[Tuple]:
        queries = [{"version": ver, "package": {"name": name, "ecosystem": ecosystem}}
                   for name, ver in deps]
        try:
            resp = self.http.session.post(
                _OSV_BATCH_URL,
                json={"queries": queries},
                timeout=_OSV_TIMEOUT,
            )
            if not resp or resp.status_code != 200:
                return []
            data    = resp.json()
            results = data.get("results", [])
            vulns   = []
            for i, result in enumerate(results):
                advisories = result.get("vulns", [])
                if advisories:
                    name, ver = deps[i]
                    vulns.append((name, ver, advisories))
            return vulns
        except Exception as e:
            logger.debug(f"OSV batch query failed: {e}")
            return []

    def _result(self, url, result_type, status, detail="", extra=None):
        r = super()._result(url, result_type, status, detail=detail)
        if extra:
            r.update(extra)
        return r


def _get_parser(filename: str):
    for key, parser in _PARSERS.items():
        if filename.endswith(key):
            return parser
    return None


def _get_ecosystem(filename: str) -> Optional[str]:
    for key, eco in _MANIFEST_ECOSYSTEM.items():
        if filename.endswith(key):
            return eco
    return None


def _osv_severity(adv: dict) -> str:
    for sev_entry in adv.get("severity", []):
        score_str = str(sev_entry.get("score", ""))
        try:
            score = float(score_str)
            if score >= 9.0:
                return "CRITICAL"
            if score >= 7.0:
                return "HIGH"
            if score >= 4.0:
                return "MEDIUM"
            return "LOW"
        except ValueError:
            pass
    return "MEDIUM"  # default


def _highest_severity(sevs: List[str]) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    for s in order:
        if s in sevs:
            return s
    return "LOW"


def _build_url(base: str, path: str) -> str:
    parsed = urlparse(base)
    return f"{parsed.scheme}://{parsed.netloc}{path}"
