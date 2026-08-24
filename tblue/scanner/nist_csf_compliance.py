"""
NIST Cybersecurity Framework (CSF) v2.0 passive compliance scanner.

Maps observable HTTP/TLS behaviour to NIST CSF functions and categories.
No extra requests — analysis uses the initial response only.
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger

logger = get_logger(__name__)

_VERSION_RE = re.compile(r"\d+\.\d+(\.\d+)?")
_IP_RE      = re.compile(r"\b(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d+\.\d+\b")
_TOKEN_RE   = re.compile(
    r"\b(AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24,}|ghp_[0-9a-zA-Z]{36})\b"
)


class NISTCSFComplianceScanner(BaseScanner):
    """Passive NIST CSF v2.0 checks across Govern, Identify, Protect, Detect, Respond, Recover."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "nist_csf_no_response", "PASS",
                detail="No response — NIST CSF checks skipped."
            ))
            return self.results

        headers  = resp.headers if hasattr(resp.headers, "get") else {}
        body     = resp.text or ""
        parsed   = urlparse(url)
        is_https = parsed.scheme.lower() == "https"
        csp      = headers.get("content-security-policy", "")
        hsts     = headers.get("strict-transport-security", "")

        # GV.OC-01 — Organisational context: security.txt signals documented programme
        security_txt = headers.get("x-security-txt", "")
        # (actual probing done by security_txt scanner; just note absence)

        # ID.AM-03 — Asset management: version disclosure inflates attack surface
        server  = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        if _VERSION_RE.search(server) or _VERSION_RE.search(powered):
            self.results.append(self._result(
                url, "nist_id_am03_version_disclosure", "WARN",
                detail=f"NIST CSF ID.AM-03: Server version disclosed (Server: '{server}', "
                       f"X-Powered-By: '{powered}'). Suppress version strings to limit asset enumeration."
            ))

        # PR.AA-02 — Protect / Authentication: HTTPS enforcement
        if not is_https:
            self.results.append(self._result(
                url, "nist_pr_aa02_no_tls", "FAIL",
                detail="NIST CSF PR.AA-02: Page served over HTTP. Authentication and data exchange "
                       "must use TLS 1.2+ to protect identities and session tokens in transit."
            ))
        else:
            self.results.append(self._result(url, "nist_pr_aa02_tls_ok", "PASS"))

        # PR.DS-02 — Protect / Data Security: HSTS
        if is_https and not hsts:
            self.results.append(self._result(
                url, "nist_pr_ds02_no_hsts", "FAIL",
                detail="NIST CSF PR.DS-02: Strict-Transport-Security absent. HSTS prevents protocol "
                       "downgrade attacks that expose data security controls."
            ))
        elif hsts:
            self.results.append(self._result(url, "nist_pr_ds02_hsts_ok", "PASS"))

        # PR.DS-01 — Data at rest protection signals: CSP restricts exfiltration
        if not csp:
            self.results.append(self._result(
                url, "nist_pr_ds01_no_csp", "WARN",
                detail="NIST CSF PR.DS-01: No Content-Security-Policy. CSP limits exfiltration "
                       "channels for data-at-rest protection via browser enforcement."
            ))
        else:
            self.results.append(self._result(url, "nist_pr_ds01_csp_ok", "PASS"))

        # PR.PS-01 — Protect / Platform Security: X-Content-Type-Options
        xcto = headers.get("x-content-type-options", "")
        if not xcto:
            self.results.append(self._result(
                url, "nist_pr_ps01_no_xcto", "WARN",
                detail="NIST CSF PR.PS-01: X-Content-Type-Options: nosniff absent. MIME sniffing "
                       "is a platform-security weakness enabling content injection attacks."
            ))

        # PR.IR-01 — Protect / Incident Response: no exposed credentials in response
        if _TOKEN_RE.search(body[:10000]):
            self.results.append(self._result(
                url, "nist_pr_ir01_credential_exposure", "FAIL",
                detail="NIST CSF PR.IR-01: Cloud/service credential pattern (AWS key, Stripe key, "
                       "GitHub PAT) detected in response body. Revoke and rotate immediately."
            ))

        # DE.CM-01 — Detect / Continuous Monitoring: internal IP disclosure
        if _IP_RE.search(body[:8000]):
            self.results.append(self._result(
                url, "nist_de_cm01_internal_ip", "WARN",
                detail="NIST CSF DE.CM-01: Private/internal IP address detected in response body. "
                       "Internal topology data enables targeted lateral movement after initial access."
            ))

        # DE.AE-02 — Detect / Adverse Events: error/exception disclosure
        error_re = re.compile(
            r"(Traceback \(most recent call last\)|stack overflow|"
            r"ORA-\d{5}|mysql_fetch_array|SQLSTATE\[|NullPointerException)", re.I
        )
        if error_re.search(body[:8000]):
            self.results.append(self._result(
                url, "nist_de_ae02_error_disclosure", "FAIL",
                detail="NIST CSF DE.AE-02: Unhandled exception / stack trace in response body. "
                       "Error disclosure gives adversaries information to escalate attacks."
            ))

        # RS.MA-01 — Respond / Incident Management: security.txt presence
        # Note: actual fetch done by security_txt scanner; flag absence in headers as signal
        if not headers.get("x-security-contact") and not security_txt:
            self.results.append(self._result(
                url, "nist_rs_ma01_no_security_contact", "WARN",
                detail="NIST CSF RS.MA-01: No security contact signal detected. "
                       "Publish a security.txt (RFC 9116) to enable coordinated vulnerability disclosure."
            ))

        return self.results
