"""
Clickjacking Deep Scanner.

Goes beyond the basic clickjacking.py check (which only examines X-Frame-Options)
to cover the full set of clickjacking mitigations and their bypass scenarios:

  1. CSP frame-ancestors vs X-Frame-Options precedence — modern browsers prefer
     frame-ancestors in CSP; XFO is the fallback. Having one without the other
     is incomplete protection.

  2. frame-ancestors 'none' vs 'self' — 'none' is stronger; 'self' allows the
     site to embed itself which can be exploited if subdomains are compromised.

  3. JavaScript frame-busting without CSP — old-style frame-busting scripts
     (if (top !== self) top.location = self.location) can be bypassed via
     sandbox iframes; CSP frame-ancestors is the only reliable protection.

  4. Sensitive pages without clickjacking protection — login, password change,
     account delete, payment, settings pages that lack both XFO and frame-ancestors.

  5. ALLOW-FROM (deprecated) — XFO: ALLOW-FROM is unsupported in modern browsers.

Read-only. Inspects headers and body of the target and common sensitive paths.

CWE-1021: Improper Restriction of Rendered UI Layers or Frames
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_SENSITIVE_PATHS = [
    "/login",
    "/account/delete",
    "/account/settings",
    "/settings",
    "/change-password",
    "/payment",
    "/checkout",
    "/transfer",
    "/admin",
    "/oauth/authorize",
    "/profile",
]

_FRAME_BUSTING_RE = re.compile(
    r'if\s*\(\s*(?:window\.)?(?:top|parent|self)\s*!==?\s*(?:window\.)?(?:self|top|parent|window)\s*\)',
    re.I
)


def _get_xfo(headers) -> Optional[str]:
    return headers.get("x-frame-options", "").strip() or None


def _get_frame_ancestors(headers) -> Optional[str]:
    csp = headers.get("content-security-policy", "")
    m = re.search(r'frame-ancestors\s+([^;]+)', csp, re.I)
    return m.group(1).strip() if m else None


def _check_protection(headers, url: str) -> List[Dict]:
    findings = []
    xfo = _get_xfo(headers)
    fa  = _get_frame_ancestors(headers)

    if not xfo and not fa:
        findings.append({
            "type": "clickjacking-no-protection",
            "status": "FAIL",
            "detail": (
                f"Neither X-Frame-Options nor CSP frame-ancestors is set at {url}.\n\n"
                f"The page can be embedded in any iframe. An attacker can use transparent "
                f"overlays to trick users into clicking UI elements they cannot see.\n\n"
                f"Fix: set 'Content-Security-Policy: frame-ancestors self' (or 'none' for "
                f"pages that should never be embedded)."
            ),
        })
        return findings

    if xfo and xfo.upper().startswith("ALLOW-FROM"):
        findings.append({
            "type": "clickjacking-xfo-allow-from-deprecated",
            "status": "WARN",
            "detail": (
                f"X-Frame-Options: {xfo!r} uses the ALLOW-FROM directive which is not "
                f"supported in Chrome, Firefox, or Safari. Use CSP frame-ancestors with "
                f"a specific origin instead."
            ),
        })

    if xfo and not fa:
        findings.append({
            "type": "clickjacking-xfo-only-no-csp",
            "status": "WARN",
            "detail": (
                f"Clickjacking protection relies only on X-Frame-Options: {xfo!r}. "
                f"CSP frame-ancestors takes precedence in modern browsers when both are set. "
                f"Using only XFO is acceptable but less robust.\n\n"
                f"Consider also setting 'Content-Security-Policy: frame-ancestors self' "
                f"to cover modern browser behaviour explicitly."
            ),
        })

    if fa:
        fa_lower = fa.lower()
        if "'self'" in fa_lower and "'none'" not in fa_lower:
            findings.append({
                "type": "clickjacking-frame-ancestors-self",
                "status": "WARN",
                "detail": (
                    f"CSP frame-ancestors is set to include 'self' ({fa!r}). Pages that "
                    f"should never be embedded (login, payment, account management) should "
                    f"use frame-ancestors 'none' for stronger protection. 'self' still "
                    f"permits embedding from same-origin pages which may be abusable if "
                    f"subdomains are attacker-controlled."
                ),
            })

    return findings


def _check_frame_busting_without_csp(body: str, headers, url: str) -> Optional[Dict]:
    fa = _get_frame_ancestors(headers)
    if fa:
        return None  # CSP is in place; frame-busting is redundant but not dangerous
    if _FRAME_BUSTING_RE.search(body[:65536]):
        return {
            "type": "clickjacking-frame-busting-js-only",
            "status": "WARN",
            "detail": (
                f"Page at {url} uses JavaScript frame-busting code but does not have "
                f"CSP frame-ancestors.\n\n"
                f"JavaScript frame-busting can be bypassed by loading the page in a "
                f"sandboxed iframe (sandbox=\"allow-scripts\" without allow-top-navigation). "
                f"CSP frame-ancestors cannot be bypassed.\n\n"
                f"Fix: replace JavaScript frame-busting with "
                f"'Content-Security-Policy: frame-ancestors self'."
            ),
        }
    return None


class ClickjackingDeepScanner(BaseScanner):
    """Deep clickjacking analysis: ALLOW-FROM, frame-ancestors, frame-busting bypass."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Clickjacking Deep — target unreachable", "PASS",
                detail="No response; deep clickjacking check skipped."))
            return self.results

        parsed      = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        found       = False

        # Check root page
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body    = resp.text or ""

        for f in _check_protection(headers, url):
            found = True
            sev = f["status"]
            if sev == "FAIL":
                log_fail(logger, f"Clickjacking Deep — {f['type']} at {url}")
            else:
                log_warn(logger, f"Clickjacking Deep — {f['type']} at {url}")
            self.results.append(self._result(url, f["type"], sev, detail=f["detail"]))

        f = _check_frame_busting_without_csp(body, headers, url)
        if f:
            found = True
            log_warn(logger, f"Clickjacking Deep — {f['type']} at {url}")
            self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        # Check sensitive paths (only flag missing protection, don't re-flag already-seen types)
        for path in _SENSITIVE_PATHS:
            ep_url = base_origin + path
            r = self.http.get(ep_url)
            if r is None or r.status_code not in (200,):
                continue
            ep_headers = {k.lower(): v for k, v in r.headers.items()}
            xfo = _get_xfo(ep_headers)
            fa  = _get_frame_ancestors(ep_headers)
            if not xfo and not fa:
                found = True
                log_warn(logger, f"Clickjacking Deep — no protection on sensitive page {ep_url}")
                self.results.append(self._result(
                    ep_url,
                    f"Clickjacking Deep — sensitive page unprotected",
                    "WARN",
                    detail=(
                        f"Sensitive page {ep_url} is accessible (HTTP 200) and has no "
                        f"clickjacking protection (no X-Frame-Options or CSP frame-ancestors).\n\n"
                        f"Sensitive operations like login, payment, and account settings "
                        f"are high-value targets for clickjacking attacks."
                    ),
                ))

        if not found:
            log_pass(logger, f"Clickjacking Deep — full protection confirmed for {url}")
            self.results.append(self._result(
                url,
                "Clickjacking Deep — protection is in place",
                "PASS",
                detail="X-Frame-Options or CSP frame-ancestors is properly configured.",
            ))

        return self.results
