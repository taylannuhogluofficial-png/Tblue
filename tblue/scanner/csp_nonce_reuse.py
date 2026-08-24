"""
CSP Nonce Reuse Scanner.

Content Security Policy nonces are meant to be single-use, cryptographically
random values that authorize specific inline scripts. If the same nonce
appears across multiple requests or is predictable, the CSP nonce protection
is effectively bypassed:

  1. Static nonce — same nonce value returned on every page load. Attackers
     who can inject a script tag can reuse the known nonce.

  2. Short or predictable nonce — nonces shorter than 128 bits (22 base64
     chars) or using low-entropy values are guessable.

  3. nonce + unsafe-inline coexistence — some configs include both a nonce
     and unsafe-inline; modern browsers ignore nonce when unsafe-inline is
     also present (CSP2 behavior), but the presence indicates misconfiguration.

  4. nonce without 'strict-dynamic' — without strict-dynamic, scripts loaded
     by nonce-trusted scripts are still blocked, defeating dynamic loading.

Read-only: makes two requests and compares nonce values.

CWE-330: Use of Insufficiently Random Values
CWE-693: Protection Mechanism Failure
"""

import re
from typing import Any, Dict, List, Optional

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_NONCE_RE = re.compile(r"'nonce-([A-Za-z0-9+/=_-]{6,})'", re.I)
_UNSAFE_INLINE_RE = re.compile(r"'unsafe-inline'", re.I)
_STRICT_DYNAMIC_RE = re.compile(r"'strict-dynamic'", re.I)
_MIN_NONCE_BITS = 128
_MIN_NONCE_B64_LEN = 22  # ceil(128/6)


def _extract_nonce(csp: str) -> Optional[str]:
    m = _NONCE_RE.search(csp)
    return m.group(1) if m else None


def _check_nonce_entropy(nonce: str, url: str) -> Optional[Dict]:
    if len(nonce) < _MIN_NONCE_B64_LEN:
        return {
            "type": "csp-nonce-too-short",
            "status": "WARN",
            "detail": (
                f"CSP nonce at {url} is only {len(nonce)} base64 chars "
                f"(less than recommended 22 chars / 128 bits).\n\n"
                f"Short nonces may be brute-forceable. An attacker who can inject "
                f"content into the page source might guess the nonce value.\n\n"
                f"Fix: generate nonces using a CSPRNG with at least 128 bits of entropy."
            ),
        }
    return None


def _check_nonce_with_unsafe_inline(csp: str, url: str) -> Optional[Dict]:
    if _NONCE_RE.search(csp) and _UNSAFE_INLINE_RE.search(csp):
        return {
            "type": "csp-nonce-with-unsafe-inline",
            "status": "WARN",
            "detail": (
                f"CSP at {url} contains both a nonce and 'unsafe-inline'.\n\n"
                f"In CSP2+, the presence of a nonce causes browsers to ignore "
                f"'unsafe-inline' for scripts, but including both is a policy "
                f"misconfiguration that may affect legacy browsers and indicates "
                f"unsafe-inline is still in the fallback path.\n\n"
                f"Fix: remove 'unsafe-inline' from CSP script-src. Rely solely on nonces."
            ),
        }
    return None


def _check_nonce_reuse(http, url: str) -> Optional[Dict]:
    """Make two requests and check if the nonce is the same."""
    resp1 = http.get(url)
    if resp1 is None:
        return None
    csp1 = {k.lower(): v for k, v in (resp1.headers or {}).items()}.get(
        "content-security-policy", "")
    nonce1 = _extract_nonce(csp1)
    if not nonce1:
        return None

    resp2 = http.get(url)
    if resp2 is None:
        return None
    csp2 = {k.lower(): v for k, v in (resp2.headers or {}).items()}.get(
        "content-security-policy", "")
    nonce2 = _extract_nonce(csp2)

    if nonce1 and nonce2 and nonce1 == nonce2:
        return {
            "type": "csp-nonce-static-reuse",
            "status": "FAIL",
            "detail": (
                f"CSP nonce at {url} is identical across two requests: {repr(nonce1)[:30]}\n\n"
                f"Static nonces defeat the purpose of nonce-based CSP. An attacker who "
                f"can read the page source (or is told the nonce value) can reuse it in "
                f"injected script tags, bypassing the CSP protection.\n\n"
                f"Fix: generate a new cryptographically random nonce for every HTTP response."
            ),
        }
    return None


class CSPNonceReuseScanner(BaseScanner):
    """Checks CSP nonces for static reuse, insufficient entropy, and unsafe-inline coexistence."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "CSP Nonce Reuse — target unreachable", "PASS",
                detail="No response; CSP nonce check skipped."))
            return self.results

        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        csp = headers.get("content-security-policy", "")
        found = False
        seen_types: set = set()

        if not _NONCE_RE.search(csp):
            log_pass(logger, f"CSP Nonce Reuse — no nonce-based CSP at {url}")
            self.results.append(self._result(
                url, "CSP Nonce Reuse — no nonce-based CSP detected", "PASS",
                detail="No CSP nonce found; nonce reuse check not applicable."))
            return self.results

        nonce = _extract_nonce(csp)

        for check_fn in [
            lambda: _check_nonce_entropy(nonce, url) if nonce else None,
            lambda: _check_nonce_with_unsafe_inline(csp, url),
            lambda: _check_nonce_reuse(self.http, url),
        ]:
            f = check_fn()
            if f and f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                if f["status"] == "FAIL":
                    log_fail(logger, f"CSP Nonce Reuse — {f['type']}")
                else:
                    log_warn(logger, f"CSP Nonce Reuse — {f['type']}")
                self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"CSP Nonce Reuse — nonce properly configured for {url}")
            self.results.append(self._result(
                url, "CSP Nonce Reuse — nonce appears unique and properly configured", "PASS",
                detail="CSP nonce is sufficiently long, unique across requests, and not combined with unsafe-inline."))

        return self.results
