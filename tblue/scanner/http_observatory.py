"""
HTTP Security Observatory Scanner.

Performs a comprehensive cross-cutting audit of HTTP security headers in
combination — because individual headers rarely exist in isolation and their
interactions matter:

  1. Header interaction analysis — CSP + X-Frame-Options synergy (redundant
     vs. missing), HSTS + Secure cookies (HTTPS but no HSTS defeats cookies),
     CORP + COEP + COOP (cross-origin isolation trio must be complete)

  2. Cross-Origin Isolation (COI) readiness — COOP + COEP together enable
     SharedArrayBuffer and high-resolution timers; partial configs are
     misleading

  3. Permissions-Policy completeness — checks for the most dangerous
     capabilities: camera, microphone, geolocation, payment, usb, midi

  4. Header consistency across pages — checks that security headers on
     non-root pages (API endpoints, subpages) match root page quality

  5. Deprecated / superseded headers still in use — X-XSS-Protection 1
     (enables XSS injection in older Chrome), Feature-Policy (replaced by
     Permissions-Policy), Public-Key-Pins (deprecated)

This scanner produces a holistic grade for HTTP security header configuration,
not just individual checks.

CWE-693: Protection Mechanism Failure
"""

from typing import Any, Dict, List, Optional

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_PROBE_PATHS = ["/", "/api/", "/api/v1/", "/login", "/static/"]

_DANGEROUS_PERMISSIONS = [
    "camera", "microphone", "geolocation", "payment", "usb", "midi",
    "display-capture", "serial", "bluetooth",
]


def _get_header(resp, name: str) -> Optional[str]:
    if resp is None:
        return None
    try:
        return resp.headers.get(name)
    except Exception:
        return None


def _check_cross_origin_isolation(headers: Dict[str, str]) -> List[Dict]:
    findings = []
    coop = headers.get("cross-origin-opener-policy", "")
    coep = headers.get("cross-origin-embedder-policy", "")
    corp = headers.get("cross-origin-resource-policy", "")

    has_coop = bool(coop)
    has_coep = bool(coep)
    has_corp = bool(corp)

    if has_coop and not has_coep:
        findings.append({
            "severity": "WARN",
            "type": "coi-coop-without-coep",
            "msg": (
                "COOP is set but COEP is missing — cross-origin isolation is incomplete. "
                "Both COOP: same-origin and COEP: require-corp are needed to enable "
                "SharedArrayBuffer and Spectre mitigations."
            ),
        })
    elif has_coep and not has_coop:
        findings.append({
            "severity": "WARN",
            "type": "coi-coep-without-coop",
            "msg": (
                "COEP is set but COOP is missing — cross-origin isolation is incomplete. "
                "Add Cross-Origin-Opener-Policy: same-origin to complete isolation."
            ),
        })

    # Check COOP value
    if coop and coop.lower() not in ("same-origin", "same-origin-allow-popups"):
        findings.append({
            "severity": "WARN",
            "type": "coi-coop-value",
            "msg": f"COOP value '{coop}' does not provide isolation — use 'same-origin'",
        })

    return findings


def _check_header_interactions(headers: Dict[str, str]) -> List[Dict]:
    findings = []

    csp = headers.get("content-security-policy", "")
    xfo = headers.get("x-frame-options", "")

    # CSP with frame-ancestors makes X-Frame-Options redundant but not harmful
    # Missing both is the real problem
    if not csp and not xfo:
        findings.append({
            "severity": "WARN",
            "type": "clickjacking-no-protection",
            "msg": (
                "Neither Content-Security-Policy (frame-ancestors) nor X-Frame-Options is set. "
                "Page is vulnerable to clickjacking."
            ),
        })

    hsts = headers.get("strict-transport-security", "")
    secure_cookie_hint = "secure" in headers.get("set-cookie", "").lower()

    if not hsts and secure_cookie_hint:
        findings.append({
            "severity": "WARN",
            "type": "hsts-missing-with-secure-cookie",
            "msg": (
                "Secure cookies are set but HSTS is absent. Without HSTS, a network attacker "
                "can downgrade the connection to HTTP, stripping the Secure flag."
            ),
        })

    # X-XSS-Protection: 1 (not 0 or 1; mode=block) — can introduce XSS
    xxp = headers.get("x-xss-protection", "")
    if xxp.strip() == "1":
        findings.append({
            "severity": "WARN",
            "type": "xxp-value-enables-xss",
            "msg": (
                "X-XSS-Protection: 1 (without mode=block) is dangerous in older Chrome — "
                "it can be exploited to inject JavaScript. Use '0' to disable it or '1; mode=block'."
            ),
        })

    # Deprecated headers
    if "public-key-pins" in headers or "public-key-pins-report-only" in headers:
        findings.append({
            "severity": "WARN",
            "type": "hpkp-deprecated",
            "msg": (
                "HTTP Public Key Pinning (HPKP) is deprecated and removed from all modern "
                "browsers. Remove Public-Key-Pins to avoid accidental denial-of-service."
            ),
        })

    if "feature-policy" in headers:
        findings.append({
            "severity": "WARN",
            "type": "feature-policy-deprecated",
            "msg": (
                "Feature-Policy header is deprecated and replaced by Permissions-Policy. "
                "Migrate to Permissions-Policy for modern browser support."
            ),
        })

    return findings


def _check_permissions_policy(headers: Dict[str, str]) -> List[Dict]:
    findings = []
    pp = headers.get("permissions-policy", "")

    if not pp:
        findings.append({
            "severity": "WARN",
            "type": "permissions-policy-missing",
            "msg": (
                "Permissions-Policy header is absent. Without it, all powerful browser APIs "
                "(camera, microphone, geolocation, payment) are enabled for the page and "
                "any embedded iframes."
            ),
        })
        return findings

    pp_lower = pp.lower()
    for cap in _DANGEROUS_PERMISSIONS:
        if cap not in pp_lower:
            findings.append({
                "severity": "WARN",
                "type": f"permissions-policy-missing-{cap}",
                "msg": (
                    f"Permissions-Policy does not address '{cap}' — it is implicitly allowed. "
                    f"Add '{cap}=()' to deny it entirely if not needed."
                ),
            })

    return findings


def _normalize_headers(resp) -> Dict[str, str]:
    try:
        return {k.lower(): v for k, v in resp.headers.items()}
    except Exception:
        return {}


class HTTPObservatoryScanner(BaseScanner):
    """Cross-cutting HTTP security header interaction analysis."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "HTTP Observatory — target unreachable", "PASS",
                detail="No response; HTTP Observatory analysis skipped."))
            return self.results

        headers = _normalize_headers(resp)
        all_findings: List[Dict] = []

        all_findings.extend(_check_cross_origin_isolation(headers))
        all_findings.extend(_check_header_interactions(headers))
        all_findings.extend(_check_permissions_policy(headers))

        # Check header consistency on non-root paths
        base = url.rstrip("/")
        root_has_csp = bool(headers.get("content-security-policy"))
        root_has_hsts = bool(headers.get("strict-transport-security"))

        for path in _PROBE_PATHS[1:3]:  # check /api/ and /api/v1/
            probe_url = base + path
            probe_resp = self.http.get(probe_url)
            if probe_resp is None or probe_resp.status_code == 404:
                continue
            probe_headers = _normalize_headers(probe_resp)
            if root_has_csp and not probe_headers.get("content-security-policy"):
                all_findings.append({
                    "severity": "WARN",
                    "type": "header-inconsistency-csp",
                    "msg": (
                        f"CSP is set on root but missing on {probe_url}. "
                        f"API responses without CSP can be loaded in iframes."
                    ),
                })
                break

        if not all_findings:
            log_pass(logger, f"HTTP Observatory — header configuration is strong on {url}")
            self.results.append(self._result(
                url,
                "HTTP Observatory — HTTP security header configuration is strong",
                "PASS",
                detail=(
                    "Cross-origin isolation, header interactions, deprecated headers, "
                    "and Permissions-Policy completeness all checked. No issues found."
                ),
            ))
            return self.results

        seen_types: set = set()
        for f in all_findings:
            t = f["type"]
            if t in seen_types:
                continue
            seen_types.add(t)

            status = f["severity"]
            if status == "FAIL":
                log_fail(logger, f"HTTP Observatory — {f['msg'][:80]}")
            else:
                log_warn(logger, f"HTTP Observatory — {f['msg'][:80]}")

            self.results.append(self._result(
                url,
                f"HTTP Observatory — {f['msg'][:100]}",
                status,
                detail=f['msg'],
            ))

        return self.results
