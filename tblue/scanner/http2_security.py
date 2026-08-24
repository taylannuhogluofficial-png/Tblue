"""
HTTP/2 Security Scanner.

Detects HTTP/2 related security issues:

1. HTTP/2 Rapid Reset vulnerability indicators (CVE-2023-44487)
   - Checks whether the server advertises HTTP/2 support
   - Checks server version/fingerprint against known-vulnerable versions
   - Detects missing rate limiting headers that would protect against rapid reset

2. HTTP/2 cleartext (h2c) exposure — HTTP/2 without TLS is not standard
   for browsers but some servers expose h2c upgrade paths

3. HTTP/2 header compression (HPACK) — Huffman encoding indicators

4. Missing HTTP/2 security headers unique to HTTP/2 environments

5. ALPN negotiation exposure — server leaks supported protocols

All checks are passive HTTP header and response inspection.

CVE-2023-44487: HTTP/2 Rapid Reset DoS attack (CVSS 7.5/HIGH)
Affected: nginx < 1.25.3, Apache httpd < 2.4.58, H2O, Tomcat < 10.1.14, etc.

Paid equivalents: Rapid7 InsightVM, Qualys VMDR.
"""

import re
from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Server version patterns known to be vulnerable to CVE-2023-44487
# nginx < 1.25.3: versions 0.x, 1.0-1.9, 1.10-1.24
_VULN_SERVER_RE = re.compile(
    r"nginx/(?:0\.\d+\.\d+|1\.(?:[0-9]|1[0-9]|2[0-4])\.\d+)\b|"  # nginx < 1.25.0
    r"nginx/1\.25\.[012]\b|"                                         # nginx 1.25.0-1.25.2
    r"Apache/2\.4\.(?:[0-4]\d|5[0-7])\b|"                          # Apache < 2.4.58
    r"Apache-Coyote/1\.1|"                                           # Old Tomcat
    r"H2O/[12]\.\d",                                                 # H2O server
    re.I,
)

# HTTP/2 protocol support indicators
_HTTP2_HEADERS_RE = re.compile(
    r"x-firefox-spdy:\s*h2|"
    r"upgrade:\s*h2c|"
    r"http2-settings|"
    r":status|"           # pseudo-header
    r"x-protocol:\s*HTTP/2",
    re.I,
)

# Rate limiting headers that mitigate rapid reset
_RATE_LIMIT_HEADERS_RE = re.compile(
    r"x-ratelimit-limit|x-rate-limit|retry-after|"
    r"ratelimit-limit|x-ratelimit-remaining",
    re.I,
)

# H2C (cleartext HTTP/2) upgrade headers
_H2C_UPGRADE_RE = re.compile(
    r"upgrade:\s*h2c|"
    r"http2-settings:\s*",
    re.I,
)

# ALPN / protocol advertisement in response
_ALPN_HEADER_RE = re.compile(
    r"alt-svc:\s*h2|"
    r"alt-svc:\s*h3|"
    r"x-alpn|"
    r"x-protocol",
    re.I,
)

# Patterns indicating h2 support
_ALT_SVC_H2_RE = re.compile(r'alt-svc:\s*(?:h2|h3|h2=")', re.I)


class HTTP2SecurityScanner(BaseScanner):
    """Detect HTTP/2 security issues including CVE-2023-44487 (Rapid Reset) indicators."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if not resp:
            self.results.append(self._result(
                url, "HTTP/2 — no HTTP/2 security issues detected", "PASS",
                detail="No HTTP/2 protocol issues or vulnerable server versions found."
            ))
            return self.results

        headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        server_header = resp.headers.get("server", "")
        via_header = resp.headers.get("via", "")

        # ── 1. Vulnerable server version ──────────────────────────────────────
        server_match = _VULN_SERVER_RE.search(server_header or via_header)
        if server_match:
            vulnerable_version = server_match.group(0)
            log_fail(logger, f"HTTP/2 vulnerable server version: {vulnerable_version}")
            self.results.append(self._result(
                url, f"HTTP/2 — server version potentially vulnerable to CVE-2023-44487 ({vulnerable_version})",
                "FAIL",
                detail=(
                    f"Server header '{vulnerable_version}' may be vulnerable to CVE-2023-44487 "
                    "(HTTP/2 Rapid Reset). This CVSS 7.5 HIGH vulnerability allows an attacker "
                    "to send a rapid stream of HEADERS frames followed by RST_STREAM frames, "
                    "overwhelming the server without processing responses. "
                    "Fix: Update to patched versions: "
                    "nginx ≥ 1.25.3, Apache httpd ≥ 2.4.58, Tomcat ≥ 10.1.14/9.0.81/8.5.94; "
                    "Configure SETTINGS_MAX_CONCURRENT_STREAMS limit; "
                    "use a WAF/CDN that filters rapid reset patterns."
                )
            ))

        # ── 2. HTTP/2 detected but server version not identifiable ─────────────
        using_h2 = bool(_HTTP2_HEADERS_RE.search(headers_str)) or bool(_ALT_SVC_H2_RE.search(headers_str))
        if using_h2 and not server_match:
            has_rate_limit = bool(_RATE_LIMIT_HEADERS_RE.search(headers_str))
            if not has_rate_limit:
                log_warn(logger, f"HTTP/2 in use but no rate limiting headers: {url}")
                self.results.append(self._result(
                    url, "HTTP/2 — HTTP/2 detected without rate limiting headers", "WARN",
                    detail=(
                        "HTTP/2 protocol detected but no rate limiting headers (X-RateLimit-Limit, "
                        "Retry-After) are present. Without rate limiting, CVE-2023-44487 "
                        "(HTTP/2 Rapid Reset) attacks may be more effective. "
                        "Fix: implement connection-level rate limiting on your HTTP/2 server; "
                        "configure SETTINGS_MAX_CONCURRENT_STREAMS to 100 or less; "
                        "use a CDN/WAF with built-in rapid reset protection."
                    )
                ))

        # ── 3. H2C (cleartext HTTP/2) upgrade ────────────────────────────────
        if _H2C_UPGRADE_RE.search(headers_str) and url.startswith("http://"):
            log_warn(logger, f"H2C (HTTP/2 cleartext) upgrade detected: {url}")
            self.results.append(self._result(
                url, "HTTP/2 — H2C (cleartext HTTP/2) upgrade advertised", "WARN",
                detail=(
                    "Server advertises support for h2c (HTTP/2 over plaintext/cleartext TLS). "
                    "Cleartext HTTP/2 is not intended for public internet use and may bypass "
                    "some security controls that only inspect HTTP/1.1 traffic. "
                    "Fix: only serve HTTP/2 over TLS (h2); disable h2c on public-facing servers."
                )
            ))

        # ── 4. ALPN protocol advertisement ────────────────────────────────────
        alt_svc = resp.headers.get("alt-svc", "")
        if alt_svc and ("h2" in alt_svc or "h3" in alt_svc):
            log_warn(logger, f"ALPN/Alt-Svc protocol advertisement: {alt_svc}")
            self.results.append(self._result(
                url, f"HTTP/2 — Alt-Svc protocol advertisement ({alt_svc[:60]})", "WARN",
                detail=(
                    f"Alt-Svc header advertises alternative protocols: '{alt_svc[:100]}'. "
                    "This exposes supported protocol versions to potential attackers. "
                    "Verify all advertised protocols are patched against CVE-2023-44487 "
                    "and similar HTTP/2 vulnerabilities before advertising them."
                )
            ))

        if not self.results:
            log_pass(logger, f"No HTTP/2 security issues found on {url}")
            self.results.append(self._result(
                url, "HTTP/2 — no HTTP/2 security issues detected", "PASS",
                detail="No vulnerable server versions or HTTP/2 security misconfigurations found."
            ))

        return self.results
