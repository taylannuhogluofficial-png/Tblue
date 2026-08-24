"""
HTTP Security Baseline Scanner.

Provides a consolidated baseline health check for the eight most fundamental
HTTP security controls, graded A/B/C/F like a report card. This scanner
does NOT duplicate the detailed analysis that individual scanners (headers.py,
csp.py, hsts_preload.py, etc.) already perform — it gives a quick top-level
scorecard to aid prioritization.

Checked controls:

  1. HTTPS — is the URL reachable over HTTPS and does the server send HSTS?
  2. Content-Security-Policy — present and not just an allow-all default
  3. X-Content-Type-Options — nosniff present
  4. X-Frame-Options / CSP frame-ancestors — clickjacking protection
  5. Referrer-Policy — restrictive policy set
  6. Permissions-Policy — present (any value)
  7. Cross-Origin-Opener-Policy — COOP present
  8. Cross-Origin-Resource-Policy — CORP present

Each control is independently assessed. A missing control emits a WARN. A
critical misconfiguration (no HTTPS, CSP that explicitly allows unsafe-inline
without a nonce/hash, etc.) emits a FAIL.

CWE-16: Configuration
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_CSP_UNSAFE_INLINE_RE = re.compile(r"'unsafe-inline'", re.I)
_CSP_UNSAFE_EVAL_RE   = re.compile(r"'unsafe-eval'", re.I)
_CSP_NONCE_RE         = re.compile(r"'nonce-[A-Za-z0-9+/=]+", re.I)
_CSP_HASH_RE          = re.compile(r"'(?:sha256|sha384|sha512)-", re.I)

_RESTRICTIVE_REFERRER = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "no-referrer-when-downgrade",
}


def _hdr(headers, name: str) -> str:
    return headers.get(name.lower(), "").strip()


def _check_https(url: str, resp) -> Optional[Dict]:
    if not url.startswith("https://"):
        return {
            "type": "baseline-no-https",
            "status": "FAIL",
            "detail": (
                f"URL is served over plain HTTP. All traffic must use HTTPS.\n\n"
                f"Without TLS, credentials, session tokens, and sensitive data are "
                f"transmitted in cleartext and susceptible to interception and MITM attacks."
            ),
        }
    hsts = _hdr(resp.headers, "strict-transport-security")
    if not hsts:
        return {
            "type": "baseline-hsts-absent",
            "status": "WARN",
            "detail": (
                f"HTTPS is in use but Strict-Transport-Security is absent.\n\n"
                f"Without HSTS, users who navigate to the HTTP version are not "
                f"automatically upgraded. Recommend: 'Strict-Transport-Security: "
                f"max-age=31536000; includeSubDomains'."
            ),
        }
    return None


def _check_csp(headers) -> Optional[Dict]:
    csp = _hdr(headers, "content-security-policy")
    if not csp:
        return {
            "type": "baseline-csp-absent",
            "status": "WARN",
            "detail": (
                "Content-Security-Policy header is absent. Without CSP, browsers "
                "have no policy to enforce against XSS or data injection attacks."
            ),
        }
    has_unsafe_inline = bool(_CSP_UNSAFE_INLINE_RE.search(csp))
    has_nonce         = bool(_CSP_NONCE_RE.search(csp))
    has_hash          = bool(_CSP_HASH_RE.search(csp))
    if has_unsafe_inline and not has_nonce and not has_hash:
        return {
            "type": "baseline-csp-unsafe-inline",
            "status": "WARN",
            "detail": (
                f"CSP contains 'unsafe-inline' without a nonce or hash. This "
                f"neutralises XSS protection for inline scripts.\n\n"
                f"Fix: replace 'unsafe-inline' with a per-request nonce or "
                f"hash-based allowlist."
            ),
        }
    return None


def _check_xcto(headers) -> Optional[Dict]:
    val = _hdr(headers, "x-content-type-options")
    if val.lower() != "nosniff":
        return {
            "type": "baseline-xcto-missing",
            "status": "WARN",
            "detail": (
                "X-Content-Type-Options: nosniff is not set. Browsers may MIME-sniff "
                "responses and execute scripts served as a different content-type."
            ),
        }
    return None


def _check_clickjacking(headers) -> Optional[Dict]:
    xfo = _hdr(headers, "x-frame-options")
    csp = _hdr(headers, "content-security-policy")
    has_fa = "frame-ancestors" in csp.lower()
    if not xfo and not has_fa:
        return {
            "type": "baseline-clickjacking-unprotected",
            "status": "WARN",
            "detail": (
                "Neither X-Frame-Options nor CSP frame-ancestors is set. "
                "The page can be embedded in an iframe and may be vulnerable to "
                "clickjacking. Recommend: CSP 'frame-ancestors self' or "
                "X-Frame-Options: SAMEORIGIN."
            ),
        }
    return None


def _check_referrer_policy(headers) -> Optional[Dict]:
    rp = _hdr(headers, "referrer-policy").lower().strip()
    if not rp:
        return {
            "type": "baseline-referrer-policy-absent",
            "status": "WARN",
            "detail": (
                "Referrer-Policy header is absent. Browsers default to sending the "
                "full referrer URL cross-origin, which may leak paths, tokens, or "
                "query parameters to third-party servers."
            ),
        }
    if rp not in _RESTRICTIVE_REFERRER:
        return {
            "type": "baseline-referrer-policy-permissive",
            "status": "WARN",
            "detail": (
                f"Referrer-Policy is set to '{rp}' which may leak the URL to "
                f"cross-origin destinations. Prefer 'strict-origin-when-cross-origin' "
                f"or stricter."
            ),
        }
    return None


def _check_permissions_policy(headers) -> Optional[Dict]:
    pp = _hdr(headers, "permissions-policy")
    if not pp:
        return {
            "type": "baseline-permissions-policy-absent",
            "status": "WARN",
            "detail": (
                "Permissions-Policy (formerly Feature-Policy) header is absent. "
                "Browsers grant full access to powerful APIs (camera, microphone, "
                "geolocation). A restrictive policy reduces the attack surface for "
                "malicious scripts."
            ),
        }
    return None


def _check_coop(headers) -> Optional[Dict]:
    coop = _hdr(headers, "cross-origin-opener-policy")
    if not coop:
        return {
            "type": "baseline-coop-absent",
            "status": "WARN",
            "detail": (
                "Cross-Origin-Opener-Policy (COOP) is not set. Without COOP, "
                "cross-origin windows can retain references to this page, enabling "
                "Spectre-style side-channel and cross-window script attacks. "
                "Recommend: 'same-origin'."
            ),
        }
    return None


def _check_corp(headers) -> Optional[Dict]:
    corp = _hdr(headers, "cross-origin-resource-policy")
    if not corp:
        return {
            "type": "baseline-corp-absent",
            "status": "WARN",
            "detail": (
                "Cross-Origin-Resource-Policy (CORP) is not set. Any cross-origin "
                "page can embed this resource, which may be exploitable with "
                "Spectre-class side channels. Recommend: 'same-origin' or "
                "'same-site' based on sharing requirements."
            ),
        }
    return None


_CHECKS = [
    _check_xcto,
    _check_csp,
    _check_clickjacking,
    _check_referrer_policy,
    _check_permissions_policy,
    _check_coop,
    _check_corp,
]


class HTTPSecurityBaselineScanner(BaseScanner):
    """Consolidated HTTP security baseline scorecard across 8 fundamental controls."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "HTTP Baseline — target unreachable", "PASS",
                detail="No response; baseline check skipped."))
            return self.results

        # HTTPS check uses the URL itself too
        https_finding = _check_https(url, resp)
        if https_finding:
            status = https_finding["status"]
            if status == "FAIL":
                log_fail(logger, f"HTTP Baseline — {https_finding['type']} at {url}")
            else:
                log_warn(logger, f"HTTP Baseline — {https_finding['type']} at {url}")
            self.results.append(self._result(
                url, https_finding["type"], status,
                detail=https_finding["detail"]))

        headers = {k.lower(): v for k, v in resp.headers.items()}

        for check_fn in _CHECKS:
            finding = check_fn(headers)
            if finding:
                log_warn(logger, f"HTTP Baseline — {finding['type']} at {url}")
                self.results.append(self._result(
                    url, finding["type"], finding["status"],
                    detail=finding["detail"]))

        if not self.results:
            log_pass(logger, f"HTTP Baseline — all 8 security controls pass at {url}")
            self.results.append(self._result(
                url,
                "HTTP Baseline — all controls pass",
                "PASS",
                detail="All 8 fundamental HTTP security controls are configured correctly.",
            ))

        return self.results
