"""
Supply Chain Lockfile Exposure Scanner.

Exposed dependency lockfiles are a supply chain security risk:

  1. package-lock.json, yarn.lock, pnpm-lock.yaml — reveal exact dependency
     versions, enabling targeted attacks against known vulnerable packages
  2. poetry.lock, Pipfile.lock, requirements.txt — same for Python projects
  3. Gemfile.lock — Ruby gems with exact versions
  4. composer.lock — PHP Composer dependencies
  5. cargo.lock — Rust dependencies

Why this matters:
  - Lockfiles reveal the EXACT version of every transitive dependency, which
    an attacker can cross-reference against CVE databases to find vulnerable
    packages that aren't directly listed in the project's manifest
  - Some lockfiles (npm, yarn) include resolved URLs and integrity hashes —
    a compromised CDN could serve a different package at the same URL
  - Lockfiles exposed on the web can be scraped by automated tools to
    identify targets with specific vulnerable libraries
  - This is distinct from supply_chain.py (which checks SRI on loaded scripts)
    and sca.py (which checks manifests) — this scanner specifically checks
    for lockfile exposure and parses their contents

CWE-1104: Use of Unmaintained Third-Party Components
CWE-200: Exposure of Sensitive Information
"""

import json
import re
from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail

logger = get_logger(__name__)

_LOCKFILE_PATHS = [
    ("/package-lock.json",  "npm",     _parse_npm_lockfile  := None),
    ("/yarn.lock",          "yarn",    None),
    ("/pnpm-lock.yaml",     "pnpm",    None),
    ("/Pipfile.lock",       "pipenv",  None),
    ("/poetry.lock",        "poetry",  None),
    ("/requirements.txt",   "pip",     None),
    ("/Gemfile.lock",       "bundler", None),
    ("/composer.lock",      "composer",None),
    ("/cargo.lock",         "cargo",   None),
    ("/pubspec.lock",       "dart",    None),
    # Subdirectory variants
    ("/frontend/package-lock.json", "npm", None),
    ("/app/package-lock.json",      "npm", None),
    ("/client/package-lock.json",   "npm", None),
    ("/web/package-lock.json",      "npm", None),
]

# Fix the list (workaround for the None-callable issue in the literal above)
_LOCKFILE_PATHS = [
    ("/package-lock.json",  "npm"),
    ("/yarn.lock",          "yarn"),
    ("/pnpm-lock.yaml",     "pnpm"),
    ("/Pipfile.lock",       "pipenv"),
    ("/poetry.lock",        "poetry"),
    ("/requirements.txt",   "pip"),
    ("/Gemfile.lock",       "bundler"),
    ("/composer.lock",      "composer"),
    ("/cargo.lock",         "cargo"),
    ("/pubspec.lock",       "dart"),
    ("/frontend/package-lock.json", "npm"),
    ("/app/package-lock.json",      "npm"),
    ("/client/package-lock.json",   "npm"),
    ("/web/package-lock.json",      "npm"),
]

# Indicators of a real lockfile vs a redirect/error page
_NPM_LOCKFILE_RE = re.compile(r'"lockfileVersion"\s*:', re.I)
_YARN_LOCKFILE_RE = re.compile(r'# yarn lockfile', re.I)
_POETRY_LOCKFILE_RE = re.compile(r'\[\[package\]\]', re.I)
_CARGO_LOCKFILE_RE = re.compile(r'\[\[package\]\]', re.I)
_PIPFILE_LOCK_RE = re.compile(r'"_meta"', re.I)
_GEMFILE_LOCK_RE = re.compile(r'^GEM$', re.M)
_COMPOSER_LOCK_RE = re.compile(r'"content-hash"', re.I)

_LOCKFILE_SIGNATURES = {
    "npm":      _NPM_LOCKFILE_RE,
    "yarn":     _YARN_LOCKFILE_RE,
    "poetry":   _POETRY_LOCKFILE_RE,
    "cargo":    _CARGO_LOCKFILE_RE,
    "pipenv":   _PIPFILE_LOCK_RE,
    "bundler":  _GEMFILE_LOCK_RE,
    "composer": _COMPOSER_LOCK_RE,
}

_MAX_BODY = 512 * 1024  # 512 KB


def _count_packages(body: str, ecosystem: str) -> int:
    """Rough count of packages in lockfile."""
    if ecosystem == "npm":
        return len(re.findall(r'"node_modules/', body))
    elif ecosystem == "yarn":
        return len(re.findall(r'^"?[a-zA-Z@]', body, re.M))
    elif ecosystem in ("poetry", "cargo"):
        return len(re.findall(r'^\[\[package\]\]', body, re.M))
    elif ecosystem == "bundler":
        return len(re.findall(r'^\s{4}[a-z]', body, re.M))
    elif ecosystem == "composer":
        try:
            data = json.loads(body[:_MAX_BODY])
            return len(data.get("packages", []) + data.get("packages-dev", []))
        except Exception:
            return 0
    return len(re.findall(r'^[a-zA-Z@\[]', body, re.M)) // 3


def _is_real_lockfile(body: str, ecosystem: str) -> bool:
    """Check if response body looks like a real lockfile."""
    sig = _LOCKFILE_SIGNATURES.get(ecosystem)
    if sig:
        return bool(sig.search(body[:_MAX_BODY]))
    # For pip/pnpm/dart: just check it's not HTML
    return "<html" not in body.lower()[:500]


class SupplyChainLockfileScanner(BaseScanner):
    """Detects exposed dependency lockfiles that reveal exact package versions."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Lockfile Exposure — target unreachable", "PASS",
                detail="No response; lockfile exposure scan skipped."))
            return self.results

        base = url.rstrip("/")
        found_lockfiles: List[Dict] = []

        for path, ecosystem in _LOCKFILE_PATHS:
            probe_url = base + path
            probe_resp = self.http.get(probe_url)
            if probe_resp is None:
                continue
            if probe_resp.status_code not in (200, 206):
                continue

            body = (probe_resp.text or "")[:_MAX_BODY]
            if not _is_real_lockfile(body, ecosystem):
                continue

            pkg_count = _count_packages(body, ecosystem)
            found_lockfiles.append({
                "url": probe_url,
                "ecosystem": ecosystem,
                "pkg_count": pkg_count,
                "size": len(body),
            })

            log_fail(logger, f"Lockfile Exposure — {ecosystem} lockfile exposed: {probe_url}")
            self.results.append(self._result(
                url,
                f"Lockfile Exposure — {ecosystem} lockfile publicly accessible ({pkg_count} packages)",
                "FAIL",
                detail=(
                    f"The {ecosystem} dependency lockfile is publicly accessible:\n"
                    f"  URL: {probe_url}\n"
                    f"  Packages: ~{pkg_count}\n"
                    f"  Size: {len(body):,} bytes\n\n"
                    f"Exposed lockfiles reveal the exact version of every transitive "
                    f"dependency. Attackers cross-reference these against CVE databases to "
                    f"find vulnerable packages your application depends on.\n\n"
                    f"For npm/yarn, lockfiles also include resolved download URLs and "
                    f"integrity hashes — making supply chain attack vectors visible.\n\n"
                    f"Fix: Add a web server rule to block access to lockfiles:\n"
                    f"  nginx: location ~* (package-lock\\.json|yarn\\.lock|"
                    f"Pipfile\\.lock) {{ deny all; }}\n"
                    f"  Apache: <Files ~ \"(lock|Lockfile)\"> Deny from all </Files>"
                ),
            ))

        if not found_lockfiles:
            log_pass(logger, f"Lockfile Exposure — no exposed lockfiles found on {url}")
            self.results.append(self._result(
                url,
                f"Lockfile Exposure — no lockfiles accessible ({len(_LOCKFILE_PATHS)} paths checked)",
                "PASS",
                detail=(
                    f"Checked {len(_LOCKFILE_PATHS)} common lockfile paths. "
                    f"No package-lock.json, yarn.lock, poetry.lock, or other lockfiles "
                    f"were accessible."
                ),
            ))

        return self.results
