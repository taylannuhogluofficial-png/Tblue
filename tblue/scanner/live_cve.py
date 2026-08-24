"""
Live CVE Scanner — real-time vulnerability matching against NVD + OSV.

This scanner:
  1. Detects software versions in the page (Server header, X-Powered-By,
     meta generator, JS library versions, package.json references, etc.)
  2. Queries NVD and OSV in real time for CVEs affecting those versions
  3. Returns findings with actual CVE IDs, CVSS scores, and fix instructions

This goes far beyond version_cve.py which uses a static embedded lookup table.
Every scan hits the live feed — the same day a CVE is published, this catches it.

Daily cache: results cached 24 hours in ~/.tblue/cve_cache/ so repeated
scans of the same target don't hammer the APIs.

CWE-1104: Use of Unmaintained Third-Party Components
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.cve_feed import match_version_cves, query_cves
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Version extraction patterns: (package_name, regex_for_version)
_VERSION_PATTERNS: List[tuple] = [
    # HTTP headers
    ("nginx",      re.compile(r"nginx/(\d+\.\d+\.\d+)", re.I)),
    ("apache",     re.compile(r"Apache/(\d+\.\d+\.\d+)", re.I)),
    ("php",        re.compile(r"PHP/(\d+\.\d+\.\d+)", re.I)),
    ("openssl",    re.compile(r"OpenSSL/(\d+\.\d+\.\d+\w*)", re.I)),
    ("express",    re.compile(r"X-Powered-By:\s*Express", re.I)),
    ("django",     re.compile(r"django[/\s](\d+\.\d+[\.\d]*)", re.I)),
    ("flask",      re.compile(r"Werkzeug/(\d+\.\d+[\.\d]*)", re.I)),
    ("wordpress",  re.compile(r"WordPress/(\d+\.\d+[\.\d]*)", re.I)),
    ("drupal",     re.compile(r"Drupal (\d+\.\d+[\.\d]*)", re.I)),
    ("spring",     re.compile(r"Spring-Boot/(\d+\.\d+[\.\d]*)", re.I)),
    # Meta generator tag
    ("wordpress",  re.compile(r'<meta[^>]+generator[^>]+WordPress[^>]+(\d+\.\d+[\.\d]*)', re.I)),
    ("drupal",     re.compile(r'<meta[^>]+generator[^>]+Drupal\s+(\d+)', re.I)),
    ("joomla",     re.compile(r'<meta[^>]+generator[^>]+Joomla\s+([\d.]+)', re.I)),
    # JS library versions in page source
    ("jquery",     re.compile(r'jquery[/\-v](\d+\.\d+\.\d+)', re.I)),
    ("react",      re.compile(r'react@(\d+\.\d+\.\d+)', re.I)),
    ("vue",        re.compile(r'vue@(\d+\.\d+\.\d+)', re.I)),
    ("angular",    re.compile(r'@angular/core@(\d+\.\d+\.\d+)', re.I)),
    ("lodash",     re.compile(r'lodash[/\-v](\d+\.\d+\.\d+)', re.I)),
    ("bootstrap",  re.compile(r'bootstrap[/\-v](\d+\.\d+\.\d+)', re.I)),
    ("moment",     re.compile(r'moment[/\-v](\d+\.\d+\.\d+)', re.I)),
    ("next",       re.compile(r'next[/\-v](\d+\.\d+\.\d+)', re.I)),
]

_MAX_VERSIONS_TO_QUERY = 10


class LiveCVEScanner(BaseScanner):
    """Real-time CVE matching via NVD and OSV feeds."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Live CVE — target unreachable", "PASS",
                detail="No response; live CVE checks skipped.",
            ))
            return self.results

        # Build corpus: headers + body
        headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items()) if resp.headers else ""
        body = (resp.text or "")[:100_000]
        corpus = headers_str + "\n" + body

        # Detect versions
        detected = self._detect_versions(corpus)

        if not detected:
            log_pass(logger, f"Live CVE — no detectable software versions found on {url}")
            self.results.append(self._result(
                url,
                "Live CVE — no detectable software versions",
                "PASS",
                detail=(
                    "No software version strings were detected in HTTP headers or page source. "
                    "This is actually good — version hiding reduces attackers' ability to "
                    "target known CVEs. The live CVE feed had nothing to match against."
                ),
            ))
            return self.results

        logger.info(f"Live CVE: detected {len(detected)} version(s): {[(d['package'], d['version']) for d in detected]}")

        # Query live CVE feed
        cve_findings = match_version_cves(url, detected)

        if cve_findings:
            for f in cve_findings:
                status = f.get("status", "WARN")
                if status == "FAIL":
                    log_fail(logger, f"Live CVE: {f['type']}")
                else:
                    log_warn(logger, f"Live CVE: {f['type']}")
                self.results.append(f)
        else:
            log_pass(logger, f"Live CVE — no known CVEs for detected versions on {url}")
            pkgs = ", ".join(f"{d['package']} {d['version']}" for d in detected[:5])
            self.results.append(self._result(
                url,
                f"Live CVE — no CVEs found for: {pkgs}",
                "PASS",
                detail=(
                    f"Queried NVD and OSV for {len(detected)} detected package version(s): {pkgs}. "
                    "No known CVEs were found in the live feed. Note: results are cached for 24 hours; "
                    "run again tomorrow to check for newly published advisories."
                ),
            ))

        return self.results

    def _detect_versions(self, corpus: str) -> List[Dict]:
        """Extract package/version pairs from the combined header+body corpus."""
        detected = []
        seen = set()

        for package, pattern in _VERSION_PATTERNS:
            m = pattern.search(corpus)
            if m:
                # Some patterns have no capture group (just detect presence)
                version = m.group(1) if m.lastindex else "unknown"
                key = f"{package}:{version}"
                if key not in seen:
                    seen.add(key)
                    detected.append({"package": package, "version": version, "location": ""})

            if len(detected) >= _MAX_VERSIONS_TO_QUERY:
                break

        return detected
