"""
Outdated JavaScript library detector.

Parses <script src="..."> URLs and inline content for known library
version strings. Cross-references against a hardcoded table of vulnerable
version ranges and associated CVEs.

Detection methods (in order of reliability):
  1. URL path pattern: /jquery-3.6.0.min.js, /libs/bootstrap/4.5.2/
  2. CDN URL: cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/
  3. Inline script comment: /*! jQuery v3.6.0 */
"""

import re
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

# ── Vulnerable version database ───────────────────────────────────────────────
# (library_name, vuln_if_below, severity, cve_summary)
_VULN_DB: List[Tuple[str, str, str, str]] = [
    ("jquery",      "3.5.0",  "HIGH",
     "CVE-2020-11022/23 (XSS via HTML parsing); CVE-2019-11358 (prototype pollution)"),
    ("bootstrap",   "3.4.1",  "MEDIUM",
     "CVE-2018-14041/42 (XSS via data-target); CVE-2016-10735 (XSS)"),
    ("bootstrap",   "4.3.1",  "MEDIUM",
     "CVE-2019-8331 (XSS via tooltip/popover data-template)"),
    ("angular",     "1.8.0",  "HIGH",
     "Multiple XSS and sandbox-escape CVEs in AngularJS 1.x"),
    ("angularjs",   "1.8.0",  "HIGH",
     "Multiple XSS and sandbox-escape CVEs in AngularJS 1.x"),
    ("lodash",      "4.17.21", "HIGH",
     "CVE-2021-23337 (command injection); CVE-2020-8203 (prototype pollution)"),
    ("underscore",  "1.13.0",  "HIGH",
     "CVE-2021-23358 (arbitrary code execution via template)"),
    ("moment",      "2.29.2",  "MEDIUM",
     "CVE-2022-24785 (path traversal); CVE-2022-31129 (ReDoS)"),
    ("handlebars",  "4.7.7",  "HIGH",
     "CVE-2021-23369/23383 (prototype pollution / code execution)"),
    ("vue",         "2.6.14",  "MEDIUM",
     "CVE-2021-41184 (XSS via v-html) — note: Vue 3.x has separate advisories"),
    ("axios",       "0.21.2",  "MEDIUM",
     "CVE-2021-3749 (ReDoS); CVE-2020-28168 (SSRF)"),
    ("highlight.js","10.4.1", "MEDIUM",
     "CVE-2021-23346 (ReDoS)"),
    ("marked",      "4.0.10", "HIGH",
     "Multiple XSS CVEs in older marked releases"),
    ("dompurify",   "2.3.4",  "HIGH",
     "CVE-2022-25887 (XSS bypass)"),
    ("prismjs",     "1.27.0", "MEDIUM",
     "CVE-2022-23647 (ReDoS)"),
    ("jquery-ui",   "1.13.0", "MEDIUM",
     "CVE-2021-41182/41183/41184 (XSS in checkboxradio/dialog/tooltip)"),
]

# ── Detection patterns ────────────────────────────────────────────────────────
# (library_slug, regex to find version in URL or inline content)
_DETECT_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("jquery",      re.compile(r"jquery[._-](\d+\.\d+\.?\d*)(\.min)?\.js", re.I)),
    ("jquery-ui",   re.compile(r"jquery[._-]ui[._-](\d+\.\d+\.?\d*)(\.min)?\.js", re.I)),
    ("jquery",      re.compile(r"/jquery/(\d+\.\d+\.?\d*)/", re.I)),
    ("jquery-ui",   re.compile(r"/jquery[-_]ui/(\d+\.\d+\.?\d*)/", re.I)),
    ("bootstrap",   re.compile(r"bootstrap[._-](\d+\.\d+\.?\d*)(\.min)?\.(?:js|css)", re.I)),
    ("bootstrap",   re.compile(r"/bootstrap/(\d+\.\d+\.?\d*)/", re.I)),
    ("angular",     re.compile(r"angular(?:js)?[._-](\d+\.\d+\.?\d*)(\.min)?\.js", re.I)),
    ("angular",     re.compile(r"/angular(?:js)?/(\d+\.\d+\.?\d*)/", re.I)),
    ("lodash",      re.compile(r"lodash[._-](\d+\.\d+\.?\d*)(\.min)?\.js", re.I)),
    ("lodash",      re.compile(r"/lodash/(\d+\.\d+\.?\d*)/", re.I)),
    ("underscore",  re.compile(r"underscore[._-](\d+\.\d+\.?\d*)(\.min)?\.js", re.I)),
    ("moment",      re.compile(r"moment[._-](\d+\.\d+\.?\d*)(\.min)?\.js", re.I)),
    ("moment",      re.compile(r"/moment(?:\.js)?/(\d+\.\d+\.?\d*)/", re.I)),
    ("handlebars",  re.compile(r"handlebars[._-](\d+\.\d+\.?\d*)(\.min)?\.js", re.I)),
    ("vue",         re.compile(r"vue[._-](\d+\.\d+\.?\d*)(\.min)?\.js", re.I)),
    ("vue",         re.compile(r"/vue/(\d+\.\d+\.?\d*)/", re.I)),
    ("axios",       re.compile(r"axios[._-](\d+\.\d+\.?\d*)(\.min)?\.js", re.I)),
    ("axios",       re.compile(r"/axios/(\d+\.\d+\.?\d*)/", re.I)),
    ("marked",      re.compile(r"marked[._-](\d+\.\d+\.?\d*)(\.min)?\.js", re.I)),
    ("dompurify",   re.compile(r"dompurify[._-](\d+\.\d+\.?\d*)(\.min)?\.js", re.I)),
    ("prismjs",     re.compile(r"prism[._-](\d+\.\d+\.?\d*)(\.min)?\.js", re.I)),
    ("highlight.js",re.compile(r"highlight[._-](\d+\.\d+\.?\d*)(\.min)?\.js", re.I)),
]

# Inline comment version patterns: /*! jQuery v3.6.0 */
_INLINE_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("jquery",     re.compile(r"/\*!?\s*jQuery\s+v?(\d+\.\d+\.?\d*)", re.I)),
    ("bootstrap",  re.compile(r"/\*!?\s*Bootstrap\s+v?(\d+\.\d+\.?\d*)", re.I)),
    ("lodash",     re.compile(r"/\*!?\s*(?:Lo-Dash|Lodash)\s+v?(\d+\.\d+\.?\d*)", re.I)),
    ("moment",     re.compile(r"/\*!?\s*moment\.js\s+v?(\d+\.\d+\.?\d*)", re.I)),
    ("vue",        re.compile(r"/\*!?\s*Vue\.js\s+v?(\d+\.\d+\.?\d*)", re.I)),
    ("handlebars", re.compile(r"/\*!?\s*Handlebars\s+v?(\d+\.\d+\.?\d*)", re.I)),
]


class JSLibraryScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        resp = self.http.get(url, allow_redirects=True)
        if not resp:
            return self.results

        html  = resp.text or ""
        found: Dict[str, str] = {}  # lib_slug → version

        # Extract script src URLs
        src_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
        for m in src_pattern.finditer(html):
            src = m.group(1)
            for lib, pattern in _DETECT_PATTERNS:
                vm = pattern.search(src)
                if vm and lib not in found:
                    found[lib] = vm.group(1)

        # Inline version comments (fetch each external script if needed)
        for lib, pattern in _INLINE_PATTERNS:
            if lib not in found:
                m = pattern.search(html)
                if m:
                    found[lib] = m.group(1)

        if not found:
            log_pass(logger, f"No detectable JS library versions found — {url}")
            self.results.append(self._result(
                url, "JS libraries — no detectable versions", "PASS",
                detail="No version strings detected in script src URLs or inline comments."
            ))
            return self.results

        flagged = False
        for lib, version in found.items():
            vuln = _check_vuln(lib, version)
            if vuln:
                sev, cves = vuln
                status = "FAIL" if sev == "HIGH" else "WARN"
                log_fail(logger, f"Outdated {lib} {version} ({sev}) — {url}") \
                    if status == "FAIL" else \
                    log_warn(logger, f"Outdated {lib} {version} ({sev}) — {url}")
                self.results.append(self._result(
                    url, f"JS library — outdated {lib} {version}", status,
                    detail=(
                        f"{lib} version {version} is outdated and has known vulnerabilities. "
                        f"CVEs: {cves}. "
                        f"Fix: upgrade to the latest stable version of {lib}."
                    )
                ))
                flagged = True
            else:
                logger.debug(f"JS library OK: {lib} {version}")

        if not flagged:
            log_pass(logger, f"All detected JS library versions look current — {url}")
            self.results.append(self._result(
                url, "JS libraries — versions appear current", "PASS",
                detail=(
                    f"Detected: {', '.join(f'{lib} {ver}' for lib, ver in found.items())}. "
                    "No known critical vulnerabilities found in these versions."
                )
            ))

        return self.results


def _check_vuln(lib: str, version: str) -> Optional[Tuple[str, str]]:
    """Return (severity, cve_summary) if the version is below the vulnerable threshold."""
    for lib_name, vuln_below, sev, cves in _VULN_DB:
        if lib_name.lower() != lib.lower():
            continue
        try:
            if _ver_lt(version, vuln_below):
                return sev, cves
        except Exception:
            pass
    return None


def _ver_lt(a: str, b: str) -> bool:
    """Return True if version a < version b (simple numeric comparison)."""
    def parts(v):
        return [int(x) for x in re.split(r"[._-]", v) if x.isdigit()]
    pa, pb = parts(a), parts(b)
    for i in range(max(len(pa), len(pb))):
        va = pa[i] if i < len(pa) else 0
        vb = pb[i] if i < len(pb) else 0
        if va < vb:
            return True
        if va > vb:
            return False
    return False
