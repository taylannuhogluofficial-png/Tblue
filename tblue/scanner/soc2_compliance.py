"""
SOC 2 Trust Services Criteria passive compliance scanner.

Maps observable HTTP behaviour to SOC 2 TSC controls (CC6, CC7, CC8, A1).
No extra HTTP requests — analysis is based on the initial response.
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger

logger = get_logger(__name__)


class SOC2ComplianceScanner(BaseScanner):
    """Passive SOC 2 Trust Services Criteria checks."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "soc2_no_response", "PASS",
                detail="No response — SOC 2 checks skipped."
            ))
            return self.results

        headers  = resp.headers if hasattr(resp.headers, "get") else {}
        body     = resp.text or ""
        parsed   = urlparse(url)
        is_https = parsed.scheme.lower() == "https"
        csp      = headers.get("content-security-policy", "")
        hsts     = headers.get("strict-transport-security", "")
        xfo      = headers.get("x-frame-options", "")
        xcto     = headers.get("x-content-type-options", "")

        # CC6.1 — Logical and Physical Access Controls: HTTPS enforcement
        if not is_https:
            self.results.append(self._result(
                url, "soc2_cc6_1_no_tls", "FAIL",
                detail="SOC 2 CC6.1: Page served over HTTP. Logical access controls require "
                       "encryption in transit (TLS 1.2+) to protect data from interception."
            ))
        else:
            self.results.append(self._result(url, "soc2_cc6_1_tls_ok", "PASS"))

        # CC6.1 — HSTS enforces HTTPS for all subsequent requests
        if is_https and not hsts:
            self.results.append(self._result(
                url, "soc2_cc6_1_no_hsts", "FAIL",
                detail="SOC 2 CC6.1: Strict-Transport-Security absent. Without HSTS, users may "
                       "connect over HTTP — bypassing logical access encryption controls."
            ))
        elif hsts:
            self.results.append(self._result(url, "soc2_cc6_1_hsts_ok", "PASS"))

        # CC6.6 — Restriction of access to protected resources: CSP
        if not csp:
            self.results.append(self._result(
                url, "soc2_cc6_6_no_csp", "WARN",
                detail="SOC 2 CC6.6: No Content-Security-Policy. CSP is a key control restricting "
                       "which origins can load/execute content, reducing XSS and data exfiltration risk."
            ))
        else:
            self.results.append(self._result(url, "soc2_cc6_6_csp_ok", "PASS"))

        # CC6.6 — X-Frame-Options prevents UI-redressing attacks on protected resources
        if not xfo and "frame-ancestors" not in csp:
            self.results.append(self._result(
                url, "soc2_cc6_6_no_frame_protection", "WARN",
                detail="SOC 2 CC6.6: No clickjacking protection (X-Frame-Options / CSP frame-ancestors). "
                       "Malicious iframes could trick users into interacting with protected data."
            ))

        # CC6.7 — Encryption of data in transit: X-Content-Type-Options to prevent MIME attacks
        if not xcto:
            self.results.append(self._result(
                url, "soc2_cc6_7_no_xcto", "WARN",
                detail="SOC 2 CC6.7: X-Content-Type-Options: nosniff absent. MIME sniffing attacks "
                       "can reinterpret content type, bypassing security controls on data responses."
            ))
        else:
            self.results.append(self._result(url, "soc2_cc6_7_xcto_ok", "PASS"))

        # CC7.1 — System operations: detect error page disclosure
        error_re = re.compile(
            r"(Traceback \(most recent call last\)|stack overflow|"
            r"ORA-\d{5}|SQL syntax|mysql_fetch_array|mysqli_|"
            r"SQLSTATE\[|psycopg2|unhandled exception)", re.I
        )
        if error_re.search(body[:8000]):
            self.results.append(self._result(
                url, "soc2_cc7_1_error_disclosure", "FAIL",
                detail="SOC 2 CC7.1: Error/stack trace disclosure in response body. System operations "
                       "must not expose internal error details that aid attacker reconnaissance."
            ))

        # CC7.2 — Monitoring: Security-related headers present
        required = {
            "strict-transport-security": "HSTS",
            "content-security-policy":   "CSP",
            "x-content-type-options":    "X-Content-Type-Options",
        }
        missing = [label for h, label in required.items() if not headers.get(h)]
        if len(missing) >= 2:
            self.results.append(self._result(
                url, "soc2_cc7_2_weak_header_posture", "WARN",
                detail=f"SOC 2 CC7.2: Multiple security headers missing ({', '.join(missing)}). "
                       "A weak header posture indicates insufficient security monitoring configuration."
            ))

        # CC8.1 — Change management: version disclosure in headers
        server  = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        version_re = re.compile(r"\d+\.\d+")
        if version_re.search(server) or version_re.search(powered):
            self.results.append(self._result(
                url, "soc2_cc8_1_version_disclosure", "WARN",
                detail=f"SOC 2 CC8.1: Software version disclosed in headers (Server: '{server}', "
                       f"X-Powered-By: '{powered}'). Version disclosure aids targeted CVE exploitation."
            ))

        # A1.1 — Availability: check for CORS misconfiguration that could affect service reliability
        acao = headers.get("access-control-allow-origin", "")
        if acao == "*" and is_https:
            self.results.append(self._result(
                url, "soc2_a1_1_cors_wildcard", "WARN",
                detail="SOC 2 A1.1: CORS Access-Control-Allow-Origin: * on HTTPS. "
                       "Wildcard CORS on authenticated services reduces availability control boundaries."
            ))

        return self.results
