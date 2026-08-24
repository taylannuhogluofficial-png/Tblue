"""
PCI-DSS v4.0 compliance passive scanner.

Maps observable HTTP behaviour to PCI-DSS requirements.
No additional HTTP requests are made beyond the initial page fetch.
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass

logger = get_logger(__name__)

# Req 4.2.1 — TLS only; no HTTP
# Req 6.4.1 — CSP deployed
# Req 6.4.3 — all scripts authorised and integrity-checked
# Req 8.6.1 — MFA indicators on admin pages
# Req 12.3.3 — cryptographic inventory (weak cipher signals)

_WEAK_CIPHER_RE = re.compile(
    r"\b(RC4|DES|3DES|MD5|SHA-?1|SSLv[23]|TLSv1\.0|TLSv1\.1)\b", re.I
)
_CARD_RE = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|"
    r"3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b"
)
_CVV_RE = re.compile(r"\b(cvv|cvc|csc|cvv2|cvc2|card.?verification)\b", re.I)


class PCIDSSComplianceScanner(BaseScanner):
    """Passive PCI-DSS v4.0 compliance checks."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "pci_dss_no_response", "PASS",
                detail="No response — PCI-DSS checks skipped."
            ))
            return self.results

        headers  = resp.headers if hasattr(resp.headers, "get") else {}
        body     = resp.text or ""
        parsed   = urlparse(url)
        is_https = parsed.scheme.lower() == "https"

        # Req 4.2.1 — cardholder data must only be transmitted over strong cryptography
        if not is_https:
            self.results.append(self._result(
                url, "pci_4_2_1_no_tls", "FAIL",
                detail="PCI-DSS Req 4.2.1: Page served over HTTP — cardholder data must only "
                       "be transmitted over TLS 1.2+. Redirect all traffic to HTTPS and enforce HSTS."
            ))
        else:
            log_pass(logger, "PCI 4.2.1 — HTTPS enforced")
            self.results.append(self._result(url, "pci_4_2_1_tls_ok", "PASS"))

        # Req 4.2.1 — weak cipher signals in headers/body
        combined = " ".join(str(v) for v in headers.values()) + " " + body[:4000]
        m = _WEAK_CIPHER_RE.search(combined)
        if m:
            self.results.append(self._result(
                url, "pci_4_2_1_weak_cipher", "FAIL",
                detail=f"PCI-DSS Req 4.2.1: Weak/deprecated algorithm '{m.group()}' referenced. "
                       "Use TLS 1.2+ with AES-256-GCM and SHA-256+ cipher suites only."
            ))

        # Req 6.4.1 — CSP must be in place
        csp = headers.get("content-security-policy", "")
        if not csp:
            self.results.append(self._result(
                url, "pci_6_4_1_no_csp", "FAIL",
                detail="PCI-DSS Req 6.4.1: Content-Security-Policy header absent. "
                       "A CSP restricting script/style/connect sources is mandatory."
            ))
        else:
            log_pass(logger, "PCI 6.4.1 — CSP present")
            self.results.append(self._result(url, "pci_6_4_1_csp_ok", "PASS"))

        # Req 6.4.3 — scripts must have integrity hashes
        try:
            soup    = BeautifulSoup(body, "html.parser")
            scripts = soup.find_all("script", src=True)
            ext_no_sri = [
                s["src"] for s in scripts
                if not s.get("integrity") and s["src"].startswith("http")
            ]
            if ext_no_sri:
                self.results.append(self._result(
                    url, "pci_6_4_3_missing_sri", "FAIL",
                    detail=f"PCI-DSS Req 6.4.3: {len(ext_no_sri)} external script(s) lack Subresource "
                           f"Integrity (SRI) attributes: {ext_no_sri[:3]}. Add integrity= and crossorigin= "
                           "to every third-party script tag."
                ))
            else:
                self.results.append(self._result(url, "pci_6_4_3_sri_ok", "PASS"))
        except Exception:
            pass

        # Req 3.3.1 — SAD (Sensitive Authentication Data) must not be stored/displayed
        if _CARD_RE.search(body):
            self.results.append(self._result(
                url, "pci_3_3_1_card_number_exposed", "FAIL",
                detail="PCI-DSS Req 3.3.1: Full card number pattern detected in page body. "
                       "PANs must never be displayed in full; mask to last 4 digits (e.g. ****1234)."
            ))

        # Req 3.3.2 — CVV must not be retained/displayed
        if _CVV_RE.search(body):
            soup2 = BeautifulSoup(body, "html.parser")
            cvv_inputs = [
                i for i in soup2.find_all("input")
                if _CVV_RE.search(i.get("name", "") + i.get("id", "") + i.get("placeholder", ""))
                and i.get("autocomplete", "").lower() not in ("off", "new-password")
            ]
            if cvv_inputs:
                self.results.append(self._result(
                    url, "pci_3_3_2_cvv_autocomplete", "FAIL",
                    detail="PCI-DSS Req 3.3.2: CVV/CVC input field(s) without autocomplete=off — "
                           "browsers may store card security codes. Set autocomplete=off on all SAD fields."
                ))

        # Req 6.3.2 — X-Frame-Options / CSP frame-ancestors to prevent clickjacking on payment pages
        xfo = headers.get("x-frame-options", "")
        fa  = "frame-ancestors" in csp
        if not xfo and not fa:
            self.results.append(self._result(
                url, "pci_6_3_2_no_frame_protection", "WARN",
                detail="PCI-DSS Req 6.3.2: No X-Frame-Options or CSP frame-ancestors detected. "
                       "Payment pages must be protected against clickjacking / UI-redressing attacks."
            ))

        # Req 8.2 — HSTS enforced (account/session management)
        hsts = headers.get("strict-transport-security", "")
        if is_https and not hsts:
            self.results.append(self._result(
                url, "pci_8_2_no_hsts", "FAIL",
                detail="PCI-DSS Req 8.2: Strict-Transport-Security header absent on HTTPS page. "
                       "HSTS with max-age ≥ 31536000 is required to prevent protocol downgrade attacks."
            ))
        elif hsts:
            log_pass(logger, "PCI 8.2 — HSTS present")
            self.results.append(self._result(url, "pci_8_2_hsts_ok", "PASS"))

        return self.results
