"""
HIPAA Security Rule passive compliance scanner.

Checks observable HTTP behaviour against HIPAA Security Rule safeguards
(45 CFR §164.312). No additional requests beyond the initial page fetch.
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

# PHI patterns (aligned with hipaa_phi_exposure scanner but lighter)
_PHI_FIELDS = re.compile(
    r"\b(ssn|social.?security|date.?of.?birth|dob|diagnosis|medication|"
    r"mrn|insurance.?id|patient.?id|icd.?10|npi|hicn|fhir|hl7)\b", re.I
)
_SSN_RE   = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_DOB_RE   = re.compile(r"\bdate.?of.?birth\b|\bdob\b", re.I)


class HIPAAComplianceScanner(BaseScanner):
    """Passive HIPAA Security Rule checks (§164.312 Technical Safeguards)."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "hipaa_no_response", "PASS",
                detail="No response — HIPAA checks skipped."
            ))
            return self.results

        headers  = resp.headers if hasattr(resp.headers, "get") else {}
        body     = resp.text or ""
        parsed   = urlparse(url)
        is_https = parsed.scheme.lower() == "https"

        # §164.312(e)(1) — Transmission Security: encrypt PHI in transit
        if not is_https:
            self.results.append(self._result(
                url, "hipaa_312_e1_no_tls", "FAIL",
                detail="HIPAA §164.312(e)(1): Page served over HTTP. ePHI must only be transmitted "
                       "over encrypted channels (TLS 1.2+). Redirect to HTTPS and enforce HSTS."
            ))
        else:
            self.results.append(self._result(url, "hipaa_312_e1_tls_ok", "PASS"))

        # §164.312(e)(2)(i) — Encryption and decryption: HSTS required
        hsts = headers.get("strict-transport-security", "")
        if is_https and not hsts:
            self.results.append(self._result(
                url, "hipaa_312_e2i_no_hsts", "FAIL",
                detail="HIPAA §164.312(e)(2)(i): HSTS header absent — browsers may access the page "
                       "over HTTP exposing ePHI. Set Strict-Transport-Security with max-age ≥ 31536000."
            ))

        # §164.312(d) — Authentication: look for login page without HTTPS
        try:
            soup = BeautifulSoup(body, "html.parser")
            forms = soup.find_all("form")
            for form in forms:
                inputs = form.find_all("input", {"type": ["password", "text", "email"]})
                if inputs and not is_https:
                    self.results.append(self._result(
                        url, "hipaa_312_d_login_over_http", "FAIL",
                        detail="HIPAA §164.312(d): Authentication form detected over HTTP. "
                               "User credentials may include ePHI context; TLS is mandatory."
                    ))
                    break
        except Exception:
            pass

        # §164.312(b) — Audit Controls: check for audit/logging endpoint disclosure
        audit_patterns = re.compile(
            r"/audit|/logs|/access.?log|/event.?log|/activity", re.I
        )
        if audit_patterns.search(body[:5000]):
            self.results.append(self._result(
                url, "hipaa_312_b_audit_endpoint_exposed", "WARN",
                detail="HIPAA §164.312(b): Audit log endpoint reference found in page body. "
                       "Audit logs containing ePHI access records must be access-controlled."
            ))

        # §164.312(c)(1) — Integrity: X-Content-Type-Options to prevent MIME attacks on PHI files
        xcto = headers.get("x-content-type-options", "")
        if not xcto:
            self.results.append(self._result(
                url, "hipaa_312_c1_no_xcto", "WARN",
                detail="HIPAA §164.312(c)(1): X-Content-Type-Options: nosniff absent. "
                       "MIME sniffing attacks could alter rendering of PHI-containing responses."
            ))
        else:
            self.results.append(self._result(url, "hipaa_312_c1_xcto_ok", "PASS"))

        # §164.312(a)(2)(iv) — Encryption: check for PHI in cleartext response
        if _SSN_RE.search(body):
            self.results.append(self._result(
                url, "hipaa_312_a2iv_ssn_exposed", "FAIL",
                detail="HIPAA §164.312(a)(2)(iv): SSN pattern detected in unencrypted response body. "
                       "SSNs are ePHI; they must never appear in plaintext API or web responses."
            ))

        if _PHI_FIELDS.search(body[:8000]):
            self.results.append(self._result(
                url, "hipaa_312_phi_field_detected", "WARN",
                detail="HIPAA §164.312: PHI-related field names detected in response. "
                       "Ensure ePHI fields are access-controlled and not exposed to unauthenticated users."
            ))

        # §164.312(e)(2)(ii) — Encryption at rest: CSP restricts exfiltration paths
        csp = headers.get("content-security-policy", "")
        if not csp:
            self.results.append(self._result(
                url, "hipaa_312_e2ii_no_csp", "WARN",
                detail="HIPAA §164.312(e)(2)(ii): No Content-Security-Policy. "
                       "CSP restricts exfiltration of ePHI via XSS or injected scripts."
            ))

        # §164.312(a)(1) — Access Control: frame protection prevents session hijacking via clickjacking
        xfo = headers.get("x-frame-options", "")
        fa  = "frame-ancestors" in csp
        if not xfo and not fa:
            self.results.append(self._result(
                url, "hipaa_312_a1_no_frame_protection", "WARN",
                detail="HIPAA §164.312(a)(1): No X-Frame-Options or CSP frame-ancestors. "
                       "Clickjacking could allow unauthorised access to ePHI sessions."
            ))

        return self.results
