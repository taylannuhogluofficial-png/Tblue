"""
Cross-Origin Policy Deep Scanner.

Three new security headers form a suite that protects against Spectre-style
attacks, cross-origin data exfiltration, and opener-based exploits:

  1. Cross-Origin-Opener-Policy (COOP) — isolates the browsing context from
     cross-origin windows. unsafe-none allows window.opener exploitation.
     Recommended: same-origin.

  2. Cross-Origin-Embedder-Policy (COEP) — prevents cross-origin resources
     from being loaded unless they opt in with CORP or CORS headers.
     Recommended: require-corp (needed for SharedArrayBuffer).

  3. Cross-Origin-Resource-Policy (CORP) — controls which origins can embed
     this resource. Missing on sensitive APIs allows cross-origin read.
     Recommended: same-site or same-origin.

  4. COOP report-only vs enforcing — report-only provides no protection;
     only logs violations.

  5. Interaction with COEP: require-corp + COOP: same-origin enables
     cross-origin isolation, which is required for SharedArrayBuffer and
     Atomics.wait(). Missing isolation means high-precision timers are
     restricted.

Read-only passive.

CWE-346: Origin Validation Error
CWE-693: Protection Mechanism Failure
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_COOP_HEADER = "cross-origin-opener-policy"
_COEP_HEADER = "cross-origin-embedder-policy"
_CORP_HEADER = "cross-origin-resource-policy"
_COOP_RO_HEADER = "cross-origin-opener-policy-report-only"
_COEP_RO_HEADER = "cross-origin-embedder-policy-report-only"

_SAFE_COOP = {"same-origin", "same-origin-allow-popups"}
_SAFE_COEP = {"require-corp", "credentialless"}
_SAFE_CORP = {"same-origin", "same-site"}


def _check_coop(headers: dict, url: str) -> Optional[Dict]:
    coop = headers.get(_COOP_HEADER, "").lower().strip()
    coop_ro = headers.get(_COOP_RO_HEADER, "")

    if not coop:
        if coop_ro:
            return {
                "type": "coop-report-only-no-enforcement",
                "status": "WARN",
                "detail": (
                    f"Cross-Origin-Opener-Policy-Report-Only is set at {url} but "
                    f"the enforcing COOP header is absent.\n\n"
                    f"Report-only provides no protection — it only logs violations. "
                    f"The browsing context can still be manipulated via window.opener.\n\n"
                    f"Fix: promote to Cross-Origin-Opener-Policy: same-origin after "
                    f"reviewing reports."
                ),
            }
        return {
            "type": "coop-missing",
            "status": "WARN",
            "detail": (
                f"No Cross-Origin-Opener-Policy header at {url}.\n\n"
                f"Without COOP, a cross-origin page that opens this page (or that this "
                f"page opens) can retain a reference through window.opener, enabling "
                f"navigation attacks and timing-based side-channels.\n\n"
                f"Fix: add Cross-Origin-Opener-Policy: same-origin."
            ),
        }

    if coop == "unsafe-none":
        return {
            "type": "coop-unsafe-none",
            "status": "WARN",
            "detail": (
                f"Cross-Origin-Opener-Policy at {url} is set to unsafe-none.\n\n"
                f"This explicitly opts out of COOP protection. Cross-origin pages can "
                f"retain opener references.\n\n"
                f"Fix: use COOP: same-origin unless you require cross-origin opener access."
            ),
        }
    return None


def _check_coep(headers: dict, url: str) -> Optional[Dict]:
    coep = headers.get(_COEP_HEADER, "").lower().strip()
    coep_ro = headers.get(_COEP_RO_HEADER, "")

    if not coep:
        if coep_ro:
            return {
                "type": "coep-report-only-no-enforcement",
                "status": "WARN",
                "detail": (
                    f"Cross-Origin-Embedder-Policy-Report-Only is set at {url} but "
                    f"the enforcing COEP header is absent.\n\n"
                    f"Without COEP enforcement, cross-origin resources can be embedded "
                    f"and read by this page, enabling Spectre-style side-channel attacks.\n\n"
                    f"Fix: promote to Cross-Origin-Embedder-Policy: require-corp."
                ),
            }
        return {
            "type": "coep-missing",
            "status": "WARN",
            "detail": (
                f"No Cross-Origin-Embedder-Policy header at {url}.\n\n"
                f"Without COEP, the page cannot achieve cross-origin isolation. "
                f"SharedArrayBuffer and high-resolution timers (needed for precision timing "
                f"attacks like Spectre) may still be available or leak cross-origin data.\n\n"
                f"Fix: add COEP: require-corp paired with COOP: same-origin for full isolation."
            ),
        }
    return None


def _check_corp(headers: dict, url: str) -> Optional[Dict]:
    corp = headers.get(_CORP_HEADER, "").lower().strip()
    if not corp:
        return {
            "type": "corp-missing",
            "status": "WARN",
            "detail": (
                f"No Cross-Origin-Resource-Policy header at {url}.\n\n"
                f"Without CORP, any cross-origin page can embed this resource and "
                f"potentially read its content via side-channels (e.g., SVG-based "
                f"cross-origin leaks, timing attacks).\n\n"
                f"Fix: add CORP: same-site (or same-origin for sensitive APIs) to "
                f"restrict which origins can load this resource."
            ),
        }
    if corp == "cross-origin":
        return {
            "type": "corp-cross-origin-too-permissive",
            "status": "WARN",
            "detail": (
                f"Cross-Origin-Resource-Policy at {url} is cross-origin (allows all).\n\n"
                f"This is appropriate only for public resources like CDN assets. "
                f"If this endpoint serves user data, cross-origin reading is possible.\n\n"
                f"Fix: use CORP: same-site for most resources."
            ),
        }
    return None


class CrossOriginPolicyDeepScanner(BaseScanner):
    """Checks COOP, COEP, CORP headers for cross-origin isolation and resource protection."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Cross-Origin Policy Deep — target unreachable", "PASS",
                detail="No response; cross-origin policy check skipped."))
            return self.results

        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        found = False

        for check_fn in [_check_coop, _check_coep, _check_corp]:
            f = check_fn(headers, url)
            if f:
                found = True
                log_warn(logger, f"Cross-Origin Policy Deep — {f['type']}")
                self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"Cross-Origin Policy Deep — all three headers present for {url}")
            self.results.append(self._result(
                url, "Cross-Origin Policy Deep — COOP/COEP/CORP all present", "PASS",
                detail="Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, and "
                       "Cross-Origin-Resource-Policy headers are all set."))

        return self.results
