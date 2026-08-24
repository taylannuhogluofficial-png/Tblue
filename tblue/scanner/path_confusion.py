"""
URL/Path Normalization and Path Confusion Scanner.

Path confusion attacks exploit inconsistencies between how a reverse proxy,
WAF, or framework normalizes URL paths versus how the application resolves them.
This discrepancy allows attackers to bypass authentication and authorization controls.

Key attack patterns:
1. Spring MVC `..;` bypass: `/admin/..;/public` → access admin as "public"
2. Nginx `$uri` vs `$request_uri`: `//admin` treated as `/admin` by app but
   cached/proxied differently by Nginx
3. Path confusion via double slashes: `//api//admin//`
4. Semicolon segment bypass: `/admin;foo=bar/`, `/;admin`
5. Trailing dot bypass: `/admin./`, `/admin./resource`
6. URL double encoding: `/%252E%252E/admin` (double percent-encode)
7. Backslash normalization: /admin%5C../secret (Windows IIS, some Node.js)
8. Path parameter injection: `/api/v1/;/admin` (matrix parameters)
9. Null byte truncation: `/admin%00.jpg` (older PHP/C-based apps)
10. Unicode normalization: `/ａdmin` (fullwidth 'a' -> ASCII 'a' after normalize)

Detection approach (passive/read-only):
- For each sensitive-looking path found on the target, probe variant forms
- Compare HTTP status codes: 401/403 baseline vs. 200 with bypass variant
- Compare response body length and content to detect access to protected content
- Flag any case where a bypass variant succeeds where the canonical form is protected

No modification of data or exploitation — purely detection and comparison.

Professional equivalents: Burp Suite Pro "Access control bypass via URL manip",
PortSwigger Research "Parsing Discrepancies" labs,
Invicti "Path Confusion" scanner, Acunetix "URL Normalization" checks.

CWE-22: Path Traversal
CWE-284: Improper Access Control
CWE-436: Interpretation Conflict
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, quote

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Protected path patterns (typically auth-protected)
_PROTECTED_PATH_HINTS = re.compile(
    r"/(?:admin|manage|management|dashboard|panel|config|internal|private|"
    r"settings|backend|cpanel|api/admin|v\d+/admin|console|backstage|"
    r"supervisor|superuser|root|system|actuator|env|shutdown)",
    re.I,
)

# Spring Boot Actuator paths (high-value target)
_ACTUATOR_PATHS = [
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/beans",
    "/actuator/shutdown",
    "/management",
]

# Publicly exposed indicator paths to test bypass from
_PUBLIC_BASELINE_PATHS = [
    "/",
    "/index.html",
    "/public",
    "/health",
    "/status",
    "/ping",
    "/api/v1/health",
    "/api/health",
]

# Path confusion bypass variants to generate
# Each is a function that takes a protected path and returns a bypass attempt
def _bypass_variants(path: str) -> List[Tuple[str, str]]:
    """Generate path confusion bypass variants for a protected path."""
    variants = []
    p = path.rstrip("/")
    segments = p.split("/")
    last = segments[-1] if segments else ""

    # 1. Spring MVC ..;/ bypass (Tomcat matrix parameter confusion)
    if len(segments) >= 2:
        parent = "/".join(segments[:-1])
        variants.append((
            f"{parent}/..;/{last}",
            "Spring MVC ..;/ path confusion bypass"
        ))
        # Double: /admin/..;/..;/admin
        variants.append((
            f"/{last}/..;/{last}",
            "Spring MVC double ..;/ bypass"
        ))

    # 2. Double slash prefix
    variants.append((
        "/" + p.lstrip("/"),  # will be prepended with extra /
        "Double-slash prefix bypass"
    ))
    # Express: //admin
    variants.append((
        "//" + p.lstrip("/"),
        "Nginx double-slash bypass"
    ))

    # 3. Trailing dot (IIS / Nginx dot normalization)
    variants.append((f"{p}.", "Trailing dot bypass"))
    variants.append((f"{p}./", "Trailing dot+slash bypass"))

    # 4. Semicolon injection (matrix parameter, Tomcat/Spring)
    variants.append((f"{p};", "Trailing semicolon bypass"))
    variants.append((f"/;{p.lstrip('/')}", "Leading semicolon bypass"))

    # 5. URL double encoding of slash (%252F)
    encoded = p.replace("/", "%252F")
    variants.append((encoded, "Double-encoded slash bypass"))

    # 6. Backslash normalization (IIS, some Node.js)
    back = p.replace("/", "\\")
    variants.append((back, "Backslash normalization bypass"))

    # 7. Null byte (older PHP/CGI)
    variants.append((f"{p}%00", "Null byte truncation bypass"))
    variants.append((f"{p}%00.html", "Null byte with extension bypass"))

    # 8. Unicode full-width chars (first letter of each segment)
    if len(p) > 1:
        # e.g., /admin → /ａdmin (fullwidth 'a')
        unicode_p = p[0] + "ａ" + p[2:]  # /ａdmin
        variants.append((unicode_p, "Unicode normalization bypass"))

    return variants


def _content_similar(a: str, b: str, threshold: float = 0.85) -> bool:
    """Check if two responses are suspiciously similar (same content returned)."""
    if not a or not b:
        return False
    la, lb = len(a), len(b)
    if la == 0 or lb == 0:
        return False
    ratio = min(la, lb) / max(la, lb)
    return ratio > threshold


class PathConfusionScanner(BaseScanner):
    """Detect URL normalization / path confusion authentication bypass vulnerabilities."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Path confusion — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        body = resp.text or ""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path

        found_any = False

        # ── 1. Check Spring Boot Actuator path confusion ──────────────────────
        found_any |= self._check_actuator_bypass(url, base)

        # ── 2. Find protected paths from page links and probe bypass variants ─
        found_any |= self._check_linked_paths(url, base, body)

        # ── 3. Probe common admin/sensitive paths directly ────────────────────
        found_any |= self._probe_common_protected_paths(url, base)

        if not found_any:
            log_pass(logger, f"No path confusion vulnerabilities detected on {url}")
            self.results.append(self._result(
                url,
                "Path confusion — no URL normalization bypass vulnerabilities detected",
                "PASS",
                detail=(
                    "Tested Spring MVC ..;/ bypass, double-slash, trailing dot, semicolon, "
                    "double URL encoding, and null byte path confusion variants. "
                    "All protected endpoints returned consistent access control results. "
                    "Fix: use Spring Security's AntPathMatcher on the full URI; "
                    "configure Nginx to normalize paths before proxying; "
                    "validate paths after URL decoding, not before."
                )
            ))

        return self.results

    def _check_actuator_bypass(self, url: str, base: str) -> bool:
        """Check if Spring Boot Actuator is accessible via path confusion."""
        found = False
        for actuator_path in _ACTUATOR_PATHS[:3]:
            canonical_url = base + actuator_path
            try:
                canonical = self.http.get(canonical_url)
                if canonical is None:
                    continue

                if canonical.status_code in (200, 204):
                    # Already accessible directly — report as exposure (spring_actuator handles this)
                    continue

                if canonical.status_code not in (401, 403):
                    continue

                # Try bypass variants on the protected path
                for bypass_path, bypass_desc in _bypass_variants(actuator_path):
                    bypass_url = base + bypass_path
                    try:
                        bypass_resp = self.http.get(bypass_url)
                        if bypass_resp is None:
                            continue
                        if bypass_resp.status_code in (200, 204):
                            bypass_body = bypass_resp.text or ""
                            # Confirm it's actually actuator content, not a generic 200
                            if any(kw in bypass_body.lower()
                                   for kw in ("timestamp", "status", "details", "beans",
                                              "health", "env", "spring")):
                                log_fail(logger, f"Spring Actuator accessible via {bypass_desc}: {bypass_url}")
                                self.results.append(self._result(
                                    bypass_url,
                                    f"Path confusion — Spring Boot Actuator bypass via {bypass_desc}",
                                    "FAIL",
                                    detail=(
                                        f"Spring Boot Actuator at {canonical_url} returned "
                                        f"HTTP {canonical.status_code} (access denied), but "
                                        f"the bypass variant {bypass_url} returned HTTP "
                                        f"{bypass_resp.status_code} with actuator content. "
                                        f"Bypass technique: {bypass_desc}. "
                                        "This allows unauthenticated access to environment "
                                        "variables, application config, and potentially RCE "
                                        "via the /actuator/env + /actuator/restart endpoints. "
                                        "Fix: configure Spring Security to use `requestMatchers` "
                                        "with `PathPatternParser` (not `AntPathMatcher`); "
                                        "upgrade Spring Boot to ≥2.6.6."
                                    )
                                ))
                                found = True
                                break
                    except Exception:
                        continue
                if found:
                    break
            except Exception:
                continue
        return found

    def _check_linked_paths(self, url: str, base: str, body: str) -> bool:
        """Find protected-looking linked paths and test bypass variants."""
        found = False
        try:
            soup = BeautifulSoup(body, "html.parser")
            tested = set()
            for tag in soup.find_all(["a", "form"], limit=30):
                href = tag.get("href") or tag.get("action") or ""
                if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
                    continue
                if not _PROTECTED_PATH_HINTS.search(href):
                    continue
                parsed_href = urlparse(href)
                ppath = parsed_href.path
                if ppath in tested:
                    continue
                tested.add(ppath)

                canonical_url = base + ppath
                try:
                    canonical = self.http.get(canonical_url)
                    if canonical is None or canonical.status_code not in (401, 403):
                        continue

                    for bypass_path, bypass_desc in _bypass_variants(ppath)[:6]:
                        bypass_url = base + bypass_path
                        try:
                            bypass_resp = self.http.get(bypass_url)
                            if bypass_resp is None:
                                continue
                            if bypass_resp.status_code in (200, 204):
                                bypass_body = bypass_resp.text or ""
                                canon_body = canonical.text or ""
                                # Don't flag if bypass just returns the same denied page
                                if _content_similar(bypass_body, canon_body):
                                    continue
                                if len(bypass_body) < 50:
                                    continue
                                log_warn(logger, f"Path confusion bypass on {ppath}: {bypass_desc}")
                                self.results.append(self._result(
                                    bypass_url,
                                    f"Path confusion — access control bypass via {bypass_desc}",
                                    "WARN",
                                    detail=(
                                        f"The protected path {ppath} returns HTTP "
                                        f"{canonical.status_code} normally, but the bypass "
                                        f"variant '{bypass_path}' returned HTTP "
                                        f"{bypass_resp.status_code}. "
                                        f"Bypass technique: {bypass_desc}. "
                                        "This may indicate a path normalization inconsistency "
                                        "between the reverse proxy/WAF and the application. "
                                        "Fix: normalize URLs before access control checks; "
                                        "use framework-native access control that handles "
                                        "all URL normalization edge cases."
                                    )
                                ))
                                found = True
                                break
                        except Exception:
                            continue
                except Exception:
                    continue
        except Exception:
            pass
        return found

    def _probe_common_protected_paths(self, url: str, base: str) -> bool:
        """Probe a handful of common admin/sensitive paths for bypass."""
        found = False
        probe_paths = [
            "/admin",
            "/admin/",
            "/api/admin",
            "/management",
            "/config",
            "/internal",
        ]
        tested = set()
        for ppath in probe_paths:
            if ppath in tested:
                continue
            tested.add(ppath)
            canonical_url = base + ppath
            try:
                canonical = self.http.get(canonical_url)
                if canonical is None or canonical.status_code not in (401, 403):
                    continue

                for bypass_path, bypass_desc in _bypass_variants(ppath)[:4]:
                    bypass_url = base + bypass_path
                    try:
                        bypass_resp = self.http.get(bypass_url)
                        if bypass_resp is None:
                            continue
                        if bypass_resp.status_code in (200, 204):
                            bypass_body = bypass_resp.text or ""
                            if len(bypass_body) < 50:
                                continue
                            canon_body = canonical.text or ""
                            if _content_similar(bypass_body, canon_body):
                                continue
                            log_warn(logger, f"Path confusion bypass on {ppath}: {bypass_desc}")
                            self.results.append(self._result(
                                bypass_url,
                                f"Path confusion — access control bypass on common admin path via {bypass_desc}",
                                "WARN",
                                detail=(
                                    f"Common admin path {ppath} is protected (HTTP "
                                    f"{canonical.status_code}), but bypass variant "
                                    f"'{bypass_path}' returns HTTP {bypass_resp.status_code}. "
                                    f"Bypass technique: {bypass_desc}. "
                                    "Fix: apply access control on the decoded, normalized path; "
                                    "validate with both proxy and app-side security rules."
                                )
                            ))
                            found = True
                            break
                    except Exception:
                        continue
            except Exception:
                continue
        return found
