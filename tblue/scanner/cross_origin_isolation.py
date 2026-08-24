"""
Cross-Origin Isolation Security Scanner.

Detects missing or misconfigured cross-origin isolation headers:

1. Cross-Origin-Opener-Policy (COOP) — prevents cross-origin windows from
   retaining a reference to this browsing context. Required for cross-origin
   isolation; blocks cross-origin window attacks.
   Values: same-origin (strongest), same-origin-allow-popups, unsafe-none
2. Cross-Origin-Embedder-Policy (COEP) — requires all sub-resources to
   explicitly opt-in via CORP or CORS headers.
   Values: require-corp (strongest), credentialless, unsafe-none
3. Cross-Origin-Resource-Policy (CORP) — prevents this resource from being
   loaded cross-origin by default.
   Values: same-site (recommended), same-origin (strictest), cross-origin

Cross-origin isolation (COOP: same-origin + COEP: require-corp) enables:
  - SharedArrayBuffer usage (needed for WebAssembly threads, audio worklets)
  - High-resolution performance.now() timers
  - Blocks Spectre-class timing attacks via process isolation

Without cross-origin isolation, browsers share process memory between
origins, enabling speculative execution side-channel attacks.

Reference: https://web.dev/cross-origin-isolation-guide/
CWE-346: Origin Validation Error
"""

from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_COOP_STRONG    = {"same-origin"}
_COOP_MODERATE  = {"same-origin-allow-popups"}
_COEP_STRONG    = {"require-corp"}
_COEP_MODERATE  = {"credentialless"}
_CORP_STRONG    = {"same-origin"}
_CORP_MODERATE  = {"same-site"}


class CrossOriginIsolationScanner(BaseScanner):
    """Detect missing/weak COOP, COEP, and CORP headers."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "Cross-origin isolation — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        h = resp.headers

        self._check_coop(url, h)
        self._check_coep(url, h)
        self._check_corp(url, h)
        self._check_isolation_combo(url, h)

        if not any(r["status"] in ("FAIL", "WARN") for r in self.results):
            log_pass(logger, f"Cross-origin isolation headers present at {url}")
            self.results.append(self._result(
                url, "Cross-origin isolation — COOP/COEP/CORP headers configured", "PASS",
                detail="COOP, COEP, and CORP headers are present with strong values."
            ))

        return self.results

    def _check_coop(self, url: str, h) -> None:
        coop = h.get("cross-origin-opener-policy", "").lower().strip()
        if not coop:
            log_warn(logger, f"Missing COOP header at {url}")
            self.results.append(self._result(
                url, "Cross-Origin-Opener-Policy — header missing", "WARN",
                detail=(
                    "Cross-Origin-Opener-Policy (COOP) is not set. Without COOP: same-origin, "
                    "cross-origin windows (opened via window.open or links) retain a reference "
                    "to this browsing context, enabling cross-origin window attacks and "
                    "blocking cross-origin process isolation. "
                    "Fix: add 'Cross-Origin-Opener-Policy: same-origin' to all page responses."
                )
            ))
        elif coop == "unsafe-none":
            log_warn(logger, f"COOP: unsafe-none at {url}")
            self.results.append(self._result(
                url, "Cross-Origin-Opener-Policy — unsafe-none disables isolation", "WARN",
                detail=(
                    "COOP is set to 'unsafe-none', which is the default and disables "
                    "cross-origin opener isolation. Cross-origin windows can still reference "
                    "this context. Fix: upgrade to 'same-origin-allow-popups' or 'same-origin'."
                )
            ))
        elif coop in _COOP_MODERATE:
            self.results.append(self._result(
                url, f"Cross-Origin-Opener-Policy — {coop} (moderate)", "WARN",
                detail=(
                    f"COOP is '{coop}', which allows popups opened by this page to retain a "
                    "reference back, reducing isolation. For full cross-origin isolation, "
                    "upgrade to 'same-origin' if popup communication is not required."
                )
            ))

    def _check_coep(self, url: str, h) -> None:
        coep = h.get("cross-origin-embedder-policy", "").lower().strip()
        if not coep:
            log_warn(logger, f"Missing COEP header at {url}")
            self.results.append(self._result(
                url, "Cross-Origin-Embedder-Policy — header missing", "WARN",
                detail=(
                    "Cross-Origin-Embedder-Policy (COEP) is not set. Without COEP: require-corp, "
                    "cross-origin resources can be embedded without opt-in, preventing "
                    "cross-origin isolation and leaving the page vulnerable to Spectre-class "
                    "side-channel attacks. "
                    "Fix: add 'Cross-Origin-Embedder-Policy: require-corp' and ensure all "
                    "sub-resources serve 'Cross-Origin-Resource-Policy: cross-origin'."
                )
            ))
        elif coep == "unsafe-none":
            self.results.append(self._result(
                url, "Cross-Origin-Embedder-Policy — unsafe-none disables embedder policy", "WARN",
                detail=(
                    "COEP is 'unsafe-none', allowing cross-origin resource embedding without opt-in. "
                    "Fix: use 'require-corp' to enforce explicit cross-origin opt-in."
                )
            ))

    def _check_corp(self, url: str, h) -> None:
        corp = h.get("cross-origin-resource-policy", "").lower().strip()
        if not corp:
            self.results.append(self._result(
                url, "Cross-Origin-Resource-Policy — header missing", "WARN",
                detail=(
                    "Cross-Origin-Resource-Policy (CORP) is not set. Without CORP, this resource "
                    "can be fetched by any origin, enabling cross-origin information leakage "
                    "via no-cors fetch or <img> tag speculation attacks (Spectre). "
                    "Fix: add 'Cross-Origin-Resource-Policy: same-site' (or 'same-origin' for "
                    "stricter isolation) to responses that should not be embedded cross-origin."
                )
            ))
        elif corp == "cross-origin":
            self.results.append(self._result(
                url, "Cross-Origin-Resource-Policy — cross-origin (broadest)", "WARN",
                detail=(
                    "CORP is 'cross-origin', allowing any origin to embed this resource. "
                    "Use 'same-site' or 'same-origin' unless this resource is intentionally "
                    "served as a public cross-origin asset (e.g., a CDN asset)."
                )
            ))

    def _check_isolation_combo(self, url: str, h) -> None:
        coop = h.get("cross-origin-opener-policy", "").lower().strip()
        coep = h.get("cross-origin-embedder-policy", "").lower().strip()

        isolated = (coop in _COOP_STRONG) and (coep in _COEP_STRONG)
        if not isolated and (coop or coep):
            self.results.append(self._result(
                url, "Cross-origin isolation — incomplete (COOP+COEP not both strong)", "WARN",
                detail=(
                    f"Full cross-origin isolation requires COOP: same-origin AND COEP: require-corp. "
                    f"Current state: COOP={coop or '(missing)'}, COEP={coep or '(missing)'}. "
                    "Without both, SharedArrayBuffer, high-resolution timers, and process "
                    "isolation remain unavailable, and Spectre mitigations are incomplete."
                )
            ))
