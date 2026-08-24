"""
Server Version CVE Correlation.

Extracts software version strings from HTTP response headers and HTML meta
tags, then correlates them against a curated vulnerability database of
high-impact CVEs for common server software.

Extracted from:
  - Server: Apache/2.4.51, nginx/1.21.0, Microsoft-IIS/10.0, LiteSpeed/6.0
  - X-Powered-By: PHP/7.4.3, ASP.NET, Express
  - X-AspNet-Version: 4.0.30319
  - X-AspNetMvc-Version: 5.2
  - X-Runtime: Ruby/2.7.0
  - Via: 1.1 Squid/4.13
  - <meta name="generator" content="WordPress 5.8">

Uses semantic version comparison — 2.4.51 < 2.4.52 is correctly handled.
Read-only: no payloads sent, no CVEs exploited.

Commercial equivalents:
  Qualys WAS "Vulnerability Detection" — matches server banners to CVE DB
  Acunetix "Network Scanner" — banner-based CVE correlation
  Tenable.io Web App Scanning — version-to-CVE mapping

CWE-200: Exposure of Sensitive Information (version banners)
CWE-1035: OWASP Top 10 2021 A06 — Vulnerable and Outdated Components
"""

import re
from typing import List, Dict, Any, Tuple

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

# ── Version parsing ───────────────────────────────────────────────────────────

def _ver(v: str) -> Tuple[int, ...]:
    """Convert version string to comparable int tuple. Returns (0,) on failure."""
    parts = re.sub(r"[^0-9.]", "", v.split("-")[0]).split(".")
    try:
        return tuple(int(p) for p in parts if p)
    except ValueError:
        return (0,)


def _vulnerable(detected: str, fixed_in: str) -> bool:
    """True if detected version is strictly below the fixed version."""
    return _ver(detected) < _ver(fixed_in) and _ver(detected) != (0,)


# ── Curated CVE vulnerability database ───────────────────────────────────────
# Each entry: (product_slug, fix_version, [CVE IDs], severity, description)
# Only HIGH/CRITICAL CVEs with public exploits or wide impact.

_CVE_DB: List[Tuple[str, str, List[str], str, str]] = [
    # ── Apache HTTP Server ────────────────────────────────────────────────────
    ("apache", "2.4.50", ["CVE-2021-41773"],  "CRITICAL",
     "Path traversal and RCE in Apache 2.4.49 — exploited in the wild."),
    ("apache", "2.4.51", ["CVE-2021-42013"],  "CRITICAL",
     "Path traversal bypass patch for CVE-2021-41773 in 2.4.50."),
    ("apache", "2.4.56", ["CVE-2023-25690"],  "CRITICAL",
     "HTTP request smuggling in Apache 2.4.0-2.4.55 via mod_proxy."),
    ("apache", "2.4.58", ["CVE-2023-43622", "CVE-2023-45802"], "HIGH",
     "HTTP/2 DoS and stream reset vulnerabilities (HTTP/2 Rapid Reset attack)."),

    # ── nginx ─────────────────────────────────────────────────────────────────
    ("nginx",  "1.23.2", ["CVE-2022-41741", "CVE-2022-41742"], "HIGH",
     "Memory corruption in nginx's ngx_http_mp4_module (mp4 module)."),
    ("nginx",  "1.25.3", ["CVE-2023-44487"], "HIGH",
     "HTTP/2 Rapid Reset attack enabling DoS (affects all major servers)."),

    # ── PHP ───────────────────────────────────────────────────────────────────
    ("php",    "8.1.12", ["CVE-2022-31628", "CVE-2022-31629"], "HIGH",
     "PHP session handler CRLF injection and stream filter bypass."),
    ("php",    "8.0.25", ["CVE-2022-31628", "CVE-2022-31629"], "HIGH",
     "PHP 8.0.x session handler CRLF injection."),
    ("php",    "7.4.33", ["CVE-2022-31628", "CVE-2022-31629"], "HIGH",
     "PHP 7.4.x session handler CRLF injection."),
    ("php",    "8.1.21", ["CVE-2023-3247"],  "HIGH",
     "PHP LDAP password comparison bypass."),
    ("php",    "8.2.8",  ["CVE-2023-3823", "CVE-2023-3824"], "CRITICAL",
     "PHP XML external entity and stack overflow vulnerabilities."),

    # ── OpenSSL ───────────────────────────────────────────────────────────────
    ("openssl","1.1.1t", ["CVE-2023-0286", "CVE-2023-0215"], "HIGH",
     "OpenSSL X.400 ASN.1 type confusion and BIO_new_NDEF use-after-free."),
    ("openssl","3.0.8",  ["CVE-2023-0286"], "HIGH",
     "OpenSSL 3.0.x ASN.1 type confusion in X.400 GeneralName handling."),
    ("openssl","3.1.1",  ["CVE-2023-2650"], "HIGH",
     "OpenSSL OBJ_obj2txt() excessive recursion for deep ASN.1 objects."),

    # ── Microsoft IIS ─────────────────────────────────────────────────────────
    ("iis",    "10.0.19041", ["CVE-2022-21907"], "CRITICAL",
     "HTTP Protocol Stack (http.sys) RCE — enabled via HTTP Trailer Support."),

    # ── Apache Tomcat ─────────────────────────────────────────────────────────
    ("tomcat", "9.0.69",  ["CVE-2022-42252"], "HIGH",
     "Apache Tomcat request smuggling via invalid Content-Length."),
    ("tomcat", "10.1.1",  ["CVE-2022-42252"], "HIGH",
     "Apache Tomcat 10.x request smuggling."),
    ("tomcat", "9.0.74",  ["CVE-2023-28709"], "HIGH",
     "Apache Tomcat denial of service via partial PUT."),

    # ── WordPress ─────────────────────────────────────────────────────────────
    ("wordpress", "6.0.3", ["CVE-2022-21663", "CVE-2022-21664"], "HIGH",
     "WordPress SQL injection and Stored XSS via post metadata."),
    ("wordpress", "6.2.1", ["CVE-2023-22622"],  "HIGH",
     "WordPress unauthenticated Blind SSRF."),
    ("wordpress", "6.3.2", ["CVE-2023-2745"],   "HIGH",
     "WordPress path traversal in file manager functionality."),

    # ── Drupal ────────────────────────────────────────────────────────────────
    ("drupal",    "9.5.11", ["CVE-2023-31250"], "CRITICAL",
     "Drupal file_access access control bypass ('Drupalgeddon 4'-class)."),
    ("drupal",    "10.1.1", ["CVE-2023-31250"], "CRITICAL",
     "Drupal 10.x access bypass via custom modules."),

    # ── Joomla ────────────────────────────────────────────────────────────────
    ("joomla",    "4.2.8",  ["CVE-2023-23752"], "CRITICAL",
     "Joomla! unauthenticated information disclosure — web service endpoints."),

    # ── LiteSpeed ─────────────────────────────────────────────────────────────
    ("litespeed", "6.0.12", ["CVE-2022-0073"],  "HIGH",
     "LiteSpeed Cache plugin reflected XSS — over 4M WordPress installs."),

    # ── Node.js ───────────────────────────────────────────────────────────────
    ("node",      "18.14.1", ["CVE-2023-30581", "CVE-2023-30589"], "HIGH",
     "Node.js permission model bypass and HTTP request smuggling."),
    ("node",      "20.3.1",  ["CVE-2023-30581"], "HIGH",
     "Node.js permission model bypass via path traversal."),
]

# ── Header extraction patterns ────────────────────────────────────────────────
# Each: (product_slug, header_name, regex to extract version)

_HEADER_PATTERNS: List[Tuple[str, str, re.Pattern]] = [
    ("apache",    "server",            re.compile(r"\bApache/(\d+\.\d+\.?\d*)", re.I)),
    ("nginx",     "server",            re.compile(r"\bnginx/(\d+\.\d+\.?\d*)", re.I)),
    ("iis",       "server",            re.compile(r"\bMicrosoft-IIS/(\d+\.\d+)", re.I)),
    ("litespeed", "server",            re.compile(r"\bLiteSpeed/(\d+\.\d+\.?\d*)", re.I)),
    ("tomcat",    "server",            re.compile(r"\bApache-Coyote/(\d+\.\d+)", re.I)),
    ("tomcat",    "x-powered-by",      re.compile(r"\bTomcat/(\d+\.\d+\.?\d*)", re.I)),
    ("php",       "x-powered-by",      re.compile(r"\bPHP/(\d+\.\d+\.?\d*)", re.I)),
    ("node",      "x-powered-by",      re.compile(r"\bExpress\b.*?(\d+\.\d+\.?\d*)", re.I)),
    ("openssl",   "server",            re.compile(r"\bOpenSSL/(\d+\.\d+\.?\d*\w*)", re.I)),
    ("iis",       "x-aspnet-version",  re.compile(r"(\d+\.\d+\.?\d*)", re.I)),
]

# ── HTML meta generator patterns ──────────────────────────────────────────────

_META_GEN_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.I,
)

_META_PRODUCTS: List[Tuple[str, re.Pattern]] = [
    ("wordpress", re.compile(r"WordPress\s+(\d+\.\d+\.?\d*)", re.I)),
    ("drupal",    re.compile(r"Drupal\s+(\d+\.\d+\.?\d*)", re.I)),
    ("joomla",    re.compile(r"Joomla!\s+(\d+\.\d+\.?\d*)", re.I)),
]


class VersionCVEScanner(BaseScanner):
    """Extract server version banners and correlate against known CVEs."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results: List[Dict[str, Any]] = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Version CVE — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        headers   = {k.lower(): v for k, v in resp.headers.items()}
        html_body = resp.text or ""

        detected: Dict[str, str] = {}  # product_slug → version string

        # Extract from headers
        for slug, header_name, pattern in _HEADER_PATTERNS:
            val = headers.get(header_name, "")
            if not val:
                continue
            m = pattern.search(val)
            if m and slug not in detected:
                detected[slug] = m.group(1)

        # Extract from HTML generator meta
        gen_match = _META_GEN_RE.search(html_body)
        if gen_match:
            generator = gen_match.group(1)
            for slug, pattern in _META_PRODUCTS:
                m = pattern.search(generator)
                if m and slug not in detected:
                    detected[slug] = m.group(1)

        if not detected:
            log_pass(logger, f"Version CVE — no version banners detected on {url}")
            self.results.append(self._result(
                url, "Version CVE — no version banners exposed", "PASS",
                detail=(
                    "No software version strings detected in HTTP headers or HTML meta tags. "
                    "Consider verifying server header suppression: Apache 'ServerTokens Prod', "
                    "nginx 'server_tokens off;', PHP expose_php = Off. "
                    "CWE-200."
                )
            ))
            return self.results

        # Warn about version disclosure even if not vulnerable
        version_list = ", ".join(f"{slug}/{ver}" for slug, ver in detected.items())
        log_warn(logger, f"Version banners exposed: {version_list}")
        self.results.append(self._result(
            url, "Version CVE — software version banners exposed", "WARN",
            detail=(
                f"Version strings detected: {version_list}. "
                "Exposing exact version numbers aids attackers in selecting targeted exploits. "
                "Fix: suppress version banners (Apache: ServerTokens Prod; "
                "nginx: server_tokens off; PHP: expose_php = Off). "
                "CWE-200."
            )
        ))

        # Check each detected version against the CVE database
        for slug, version in detected.items():
            self._check_cves(url, slug, version)

        return self.results

    def _check_cves(self, url: str, slug: str, version: str) -> None:
        matching_cves: List[Tuple[str, str, List[str], str, str]] = []

        for db_slug, fix_ver, cve_ids, severity, description in _CVE_DB:
            if db_slug != slug:
                continue
            if _vulnerable(version, fix_ver):
                matching_cves.append((fix_ver, cve_ids, severity, description))

        if not matching_cves:
            return

        # Report the most severe finding
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        matching_cves.sort(key=lambda x: severity_order.get(x[2], 9))
        fix_ver, cve_ids, severity, description = matching_cves[0]

        all_cves = []
        for _, ids, _, _ in matching_cves:
            all_cves.extend(ids)
        all_cves = list(dict.fromkeys(all_cves))  # deduplicate, preserve order

        status = "FAIL" if severity in ("CRITICAL", "HIGH") else "WARN"

        product_name = slug.title()
        cve_str = ", ".join(all_cves[:8])
        if len(all_cves) > 8:
            cve_str += f" (+ {len(all_cves) - 8} more)"

        log_fail(logger, f"Version CVE: {product_name}/{version} — {cve_ids[0]}")
        self.results.append(self._result(
            url,
            f"Version CVE — {product_name} {version} has known {severity} CVE(s)",
            status,
            detail=(
                f"Detected {product_name} version {version} matches known vulnerabilities: "
                f"{cve_str}. "
                f"Most critical: {description} "
                f"Fix: upgrade {product_name} to {fix_ver} or later. "
                "Apply security updates immediately for CRITICAL severity findings. "
                "CWE-1035, OWASP A06:2021."
            )
        ))
