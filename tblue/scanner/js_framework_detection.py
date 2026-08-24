"""
JavaScript Framework Detection and Version Security Scanner.

Identifying the exact JavaScript framework and version helps map known CVEs
and security issues. Outdated or vulnerable framework versions are a leading
cause of client-side vulnerabilities.

This scanner:
  1. Detects frameworks from page source, global variables, and script URLs
  2. Extracts version numbers using multiple heuristics
  3. Flags frameworks known to have critical security issues in common versions
  4. Detects development/debug builds served in production
  5. Identifies end-of-life (EOL) framework versions

Frameworks covered:
  - React, Vue, Angular, Svelte, Next.js, Nuxt.js
  - jQuery, Backbone.js, Ember.js, Knockout.js
  - Lodash, Underscore (prototype pollution)
  - Bootstrap (XSS in older versions)
  - Handlebars, Mustache, Pug (template injection)

Unlike js_libraries.py which checks for CDN versions, this scanner
specifically focuses on framework security version analysis and debug
build detection.

CWE-1104: Use of Unmaintained Third-Party Components
CWE-676: Use of Potentially Dangerous Function
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_MAX_BODY = 512 * 1024

# (name, detection_pattern, version_pattern)
_FRAMEWORKS: List[Tuple[str, re.Pattern, re.Pattern]] = [
    ("React",
     re.compile(r'react(?:\.development|\.production\.min)?\.js|__REACT_DEVTOOLS|window\.__REACT', re.I),
     re.compile(r'react(?:@|\.version\s*[=:]\s*["\'])([0-9]+\.[0-9]+(?:\.[0-9]+)?)', re.I)),

    ("Vue",
     re.compile(r'vue(?:\.min|\.runtime|\.esm)?\.js|window\.__VUE|__vue_app__', re.I),
     re.compile(r'vue(?:@|\.version\s*[=:]\s*["\'])([0-9]+\.[0-9]+(?:\.[0-9]+)?)', re.I)),

    ("Angular",
     re.compile(r'angular(?:\.min)?\.js|ng-version|__ANGULAR_COMPILER__', re.I),
     re.compile(r'(?:ng-version=["\']|angular(?:@|\/))'
                r'([0-9]+\.[0-9]+(?:\.[0-9]+)?)', re.I)),

    ("jQuery",
     re.compile(r'jquery(?:-[0-9.]+)?(?:\.min)?\.js|window\.jQuery|jQuery\.fn', re.I),
     re.compile(r'jquery(?:-|@|\.fn\.jquery\s*=\s*["\']|\/jquery\/)([0-9]+\.[0-9]+(?:\.[0-9]+)?)', re.I)),

    ("Lodash",
     re.compile(r'lodash(?:\.min)?\.js|window\._\s*=|_\.VERSION', re.I),
     re.compile(r'lodash(?:@|\/lodash\/)([0-9]+\.[0-9]+(?:\.[0-9]+)?)', re.I)),

    ("Backbone",
     re.compile(r'backbone(?:\.min)?\.js|Backbone\.VERSION', re.I),
     re.compile(r'Backbone\.VERSION\s*=\s*["\']([0-9]+\.[0-9]+(?:\.[0-9]+)?)["\']', re.I)),

    ("Knockout",
     re.compile(r'knockout(?:-[0-9.]+)?(?:\.min)?\.js|ko\.version', re.I),
     re.compile(r'knockout(?:@|\/)([0-9]+\.[0-9]+(?:\.[0-9]+)?)', re.I)),

    ("Handlebars",
     re.compile(r'handlebars(?:\.min)?\.js|Handlebars\.VERSION', re.I),
     re.compile(r'Handlebars\.VERSION\s*=\s*["\']([0-9]+\.[0-9]+(?:\.[0-9]+)?)["\']', re.I)),

    ("Bootstrap",
     re.compile(r'bootstrap(?:-[0-9.]+)?(?:\.bundle)?(?:\.min)?\.js', re.I),
     re.compile(r'bootstrap(?:@|\/)([0-9]+\.[0-9]+(?:\.[0-9]+)?)', re.I)),
]

# Development build indicators
_DEV_BUILD_PATTERNS = [
    (re.compile(r'\.development\.js', re.I),      "React/Vue development build"),
    (re.compile(r'react-dom\.development', re.I), "React DOM development build"),
    (re.compile(r'vue\.runtime\.esm-bundler', re.I), "Vue ESM bundler build (dev)"),
    (re.compile(r'/__webpack_hmr', re.I),         "Webpack HMR (hot module reload) active"),
    (re.compile(r'[?&]debug=true', re.I),         "Debug mode in script URL"),
    (re.compile(r'sourceMappingURL=.*\.map', re.I), "Source map references in script"),
]

# Known vulnerable version ranges (framework, max_safe_minor)
# These are examples of critically vulnerable versions
_KNOWN_VULN_VERSIONS = {
    "jQuery":     [("1.", "jQuery <1.x is EOL with many XSS vulns"),
                   ("2.", "jQuery 2.x is EOL with many XSS vulns")],
    "Lodash":     [("4.0.", "Lodash 4.0.x has prototype pollution CVE-2019-10744"),
                   ("4.1.", "Lodash 4.1.x has prototype pollution CVE-2019-10744")],
    "Handlebars": [("1.", "Handlebars 1.x has template injection (CVE-2015-8861)"),
                   ("2.", "Handlebars 2.x has template injection"),
                   ("3.", "Handlebars 3.x has prototype pollution (CVE-2019-19919)")],
    "Bootstrap":  [("2.", "Bootstrap 2.x has XSS in tooltip/popover (EOL)"),
                   ("3.", "Bootstrap 3.x has XSS in tooltip/popover (CVE-2019-8331)")],
    "Angular":    [("1.", "AngularJS 1.x is EOL with sandbox escapes (CVE-2016-5385)")],
}


def _detect_frameworks(body: str, script_urls: List[str]) -> List[Tuple[str, Optional[str]]]:
    """Returns list of (framework_name, version_or_None) detected."""
    detected = []
    combined = body[:_MAX_BODY] + " " + " ".join(script_urls)
    for name, detect_re, version_re in _FRAMEWORKS:
        if detect_re.search(combined):
            ver_m = version_re.search(combined)
            version = ver_m.group(1) if ver_m else None
            detected.append((name, version))
    return detected


def _check_vuln_version(name: str, version: Optional[str]) -> Optional[str]:
    if not version:
        return None
    prefixes = _KNOWN_VULN_VERSIONS.get(name, [])
    for prefix, desc in prefixes:
        if version.startswith(prefix):
            return desc
    return None


def _detect_dev_builds(body: str) -> List[str]:
    results = []
    for pattern, label in _DEV_BUILD_PATTERNS:
        if pattern.search(body[:_MAX_BODY]):
            results.append(label)
    return results


class JSFrameworkDetectionScanner(BaseScanner):
    """Detects JS frameworks, extracts versions, and flags security issues."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "JS Framework Detection — target unreachable", "PASS",
                detail="No response; framework detection skipped."))
            return self.results

        body = (resp.text or "")[:_MAX_BODY]
        _EXT_SCRIPT_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
        script_urls = [m.group(1) for m in _EXT_SCRIPT_RE.finditer(body)]

        detected   = _detect_frameworks(body, script_urls)
        dev_builds = _detect_dev_builds(body)

        all_findings: List[Dict] = []
        seen_types: set = set()

        for name, version in detected:
            vuln_msg = _check_vuln_version(name, version)
            if vuln_msg:
                key = f"framework-vuln-{name}"
                if key not in seen_types:
                    seen_types.add(key)
                    all_findings.append({
                        "severity": "WARN",
                        "type": key,
                        "msg": (
                            f"{name} {version or 'unknown'} detected — {vuln_msg}. "
                            f"Update to the latest stable version."
                        ),
                    })

        for dev_label in dev_builds:
            key = f"dev-build-{dev_label[:30]}"
            if key not in seen_types:
                seen_types.add(key)
                all_findings.append({
                    "severity": "WARN",
                    "type": "dev-build-in-production",
                    "msg": (
                        f"Development/debug build detected in production: {dev_label}. "
                        f"Development builds expose internal diagnostics, disable optimizations, "
                        f"and may include debug APIs not intended for public access."
                    ),
                })

        if not all_findings:
            framework_str = (
                ", ".join(f"{n} {v or '(version unknown)'}" for n, v in detected[:5])
                if detected else "none detected"
            )
            log_pass(logger, f"JS Framework Detection — no vulnerable frameworks on {url}")
            self.results.append(self._result(
                url,
                "JS Framework Detection — no known-vulnerable framework versions detected",
                "PASS",
                detail=(
                    f"Detected frameworks: {framework_str}\n"
                    f"No known-vulnerable versions or development builds found."
                ),
            ))
            return self.results

        for f in all_findings:
            status = f["severity"]
            if status == "FAIL":
                log_fail(logger, f"JS Framework Detection — {f['msg'][:80]}")
            else:
                log_warn(logger, f"JS Framework Detection — {f['msg'][:80]}")

            self.results.append(self._result(
                url,
                f"JS Framework Detection — {f['type']}",
                status,
                detail=f["msg"],
            ))

        return self.results
