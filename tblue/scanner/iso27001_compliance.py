"""
ISO/IEC 27001:2022 passive compliance scanner.

Maps observable HTTP behaviour to ISO 27001:2022 Annex A controls.
No extra HTTP requests — analysis uses the initial response only.
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_VERSION_RE  = re.compile(r"\d+\.\d+")
_SECRET_RE   = re.compile(
    r"(AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{24,}|ghp_[0-9a-zA-Z]{36}|"
    r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)", re.M
)
_INTERNAL_RE = re.compile(
    r"\b(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+|"
    r"192\.168\.\d+\.\d+|localhost|127\.0\.0\.1)\b"
)


class ISO27001ComplianceScanner(BaseScanner):
    """Passive ISO/IEC 27001:2022 Annex A controls check."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "iso27001_no_response", "PASS",
                detail="No response — ISO 27001 checks skipped."
            ))
            return self.results

        headers  = resp.headers if hasattr(resp.headers, "get") else {}
        body     = resp.text or ""
        parsed   = urlparse(url)
        is_https = parsed.scheme.lower() == "https"
        csp      = headers.get("content-security-policy", "")
        hsts     = headers.get("strict-transport-security", "")

        # A.8.20 — Networks security: TLS enforcement
        if not is_https:
            self.results.append(self._result(
                url, "iso27001_a8_20_no_tls", "FAIL",
                detail="ISO 27001:2022 A.8.20 (Network Security): Page served over HTTP. "
                       "All network communications transmitting sensitive data must be encrypted (TLS 1.2+)."
            ))
        else:
            self.results.append(self._result(url, "iso27001_a8_20_tls_ok", "PASS"))

        # A.8.20 — HSTS pins HTTPS for future requests
        if is_https and not hsts:
            self.results.append(self._result(
                url, "iso27001_a8_20_no_hsts", "FAIL",
                detail="ISO 27001:2022 A.8.20: HSTS absent — browsers may negotiate HTTP, "
                       "bypassing network security controls. Add Strict-Transport-Security: max-age=31536000."
            ))
        elif hsts:
            self.results.append(self._result(url, "iso27001_a8_20_hsts_ok", "PASS"))

        # A.8.9 — Configuration management: version disclosure
        server  = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        if _VERSION_RE.search(server) or _VERSION_RE.search(powered):
            self.results.append(self._result(
                url, "iso27001_a8_9_version_disclosure", "WARN",
                detail=f"ISO 27001:2022 A.8.9 (Configuration Management): Version information exposed "
                       f"(Server: '{server}', X-Powered-By: '{powered}'). Remove version strings to "
                       "prevent targeted vulnerability exploitation."
            ))

        # A.8.3 — Information access restriction: frame protection
        xfo = headers.get("x-frame-options", "")
        if not xfo and "frame-ancestors" not in csp:
            self.results.append(self._result(
                url, "iso27001_a8_3_no_frame_protection", "WARN",
                detail="ISO 27001:2022 A.8.3 (Information Access Restriction): No X-Frame-Options or "
                       "CSP frame-ancestors. Clickjacking enables unauthorised access to restricted information."
            ))

        # A.8.24 — Use of cryptography: CSP as exfiltration control
        if not csp:
            self.results.append(self._result(
                url, "iso27001_a8_24_no_csp", "WARN",
                detail="ISO 27001:2022 A.8.24 (Use of Cryptography): Content-Security-Policy absent. "
                       "CSP is a mandatory control limiting script execution and data exfiltration vectors."
            ))
        else:
            self.results.append(self._result(url, "iso27001_a8_24_csp_ok", "PASS"))

        # A.8.12 — Data leakage prevention: secrets in response
        if _SECRET_RE.search(body[:10000]):
            self.results.append(self._result(
                url, "iso27001_a8_12_secret_exposure", "FAIL",
                detail="ISO 27001:2022 A.8.12 (Data Leakage Prevention): Credential or private key "
                       "pattern detected in response body. Revoke immediately and add DLP controls."
            ))

        # A.8.12 — Internal topology in response body
        if _INTERNAL_RE.search(body[:8000]):
            self.results.append(self._result(
                url, "iso27001_a8_12_internal_ip_disclosure", "WARN",
                detail="ISO 27001:2022 A.8.12: Internal IP / hostname in response. "
                       "Internal network topology disclosure assists lateral movement."
            ))

        # A.5.14 — Information transfer: X-Content-Type-Options
        xcto = headers.get("x-content-type-options", "")
        if not xcto:
            self.results.append(self._result(
                url, "iso27001_a5_14_no_xcto", "WARN",
                detail="ISO 27001:2022 A.5.14 (Information Transfer): X-Content-Type-Options: nosniff "
                       "absent. MIME sniffing may alter how transferred information is processed."
            ))
        else:
            self.results.append(self._result(url, "iso27001_a5_14_xcto_ok", "PASS"))

        # A.6.8 — Information security event reporting: security.txt
        # (full check done by security_txt scanner)
        if not headers.get("x-security-contact"):
            self.results.append(self._result(
                url, "iso27001_a6_8_no_disclosure_policy", "WARN",
                detail="ISO 27001:2022 A.6.8 (Information Security Event Reporting): No security "
                       "disclosure contact detected. Publish security.txt (RFC 9116) at "
                       "/.well-known/security.txt."
            ))

        # A.8.23 — Web filtering: check for mixed content signals
        try:
            soup    = BeautifulSoup(body, "html.parser")
            http_srcs = [
                tag.get("src") or tag.get("href", "")
                for tag in soup.find_all(["script", "link", "img"])
                if (tag.get("src") or tag.get("href", "")).startswith("http://")
            ]
            if http_srcs and is_https:
                self.results.append(self._result(
                    url, "iso27001_a8_23_mixed_content", "WARN",
                    detail=f"ISO 27001:2022 A.8.23 (Web Filtering): {len(http_srcs)} HTTP resource(s) "
                           "loaded on HTTPS page. Mixed content undermines TLS transport security."
                ))
        except Exception:
            pass

        return self.results
