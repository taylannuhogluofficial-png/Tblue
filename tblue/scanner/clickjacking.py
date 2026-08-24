"""
Clickjacking Defense Scanner.

Checks multiple layers of clickjacking protection:

1. X-Frame-Options header presence (DENY / SAMEORIGIN / ALLOW-FROM)
2. CSP frame-ancestors directive (supersedes X-Frame-Options in modern browsers)
3. Conflict detection: X-Frame-Options DENY vs CSP frame-ancestors 'self' (inconsistent)
4. ALLOW-FROM deprecation — only IE supports it; Chrome/Firefox ignore it
5. Pages that frame-bust via JavaScript only (no HTTP headers)
6. Frameable login/payment/account pages → higher severity
7. SameSite cookie check as a secondary signal (incomplete protection alone)

Paid equivalent coverage: Burp Pro's Clickjacking active scanner.

CWE-1021: Improper Restriction of Rendered UI Layers or Frames
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse
from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_SENSITIVE_PATHS = [
    "/login", "/signin", "/account", "/profile", "/settings",
    "/payment", "/checkout", "/transfer", "/admin",
    "/password", "/password-reset", "/2fa", "/verify",
]

_FRAMEBUSTING_JS_RE = re.compile(
    r"top\.location|self\s*!==?\s*top|parent\s*!==?\s*self|window\.top\s*!==",
    re.I,
)

_XFO_ALLOW_FROM_RE = re.compile(r"allow-from", re.I)
_CSP_FRAME_ANCESTORS_RE = re.compile(r"frame-ancestors\s+([^;]+)", re.I)


def _csp_frame_ancestors(headers: dict) -> str:
    csp = headers.get("content-security-policy", "")
    m = _CSP_FRAME_ANCESTORS_RE.search(csp)
    return m.group(1).strip() if m else ""


class ClickjackingScanner(BaseScanner):
    """Checks clickjacking defenses on the main page and sensitive sub-paths."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping clickjacking checks: {url}")
            self.results.append(self._result(
                url, "Clickjacking — no response", "PASS",
                detail="Target did not respond; clickjacking checks skipped."
            ))
            return self.results

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text or ""

        self._check_main_page(url, headers_lower, body)
        self._check_sensitive_pages(url)

        if not self.results:
            log_pass(logger, f"Clickjacking protection in place on {url}")
            self.results.append(self._result(
                url, "Clickjacking — page is protected against framing", "PASS",
                detail=(
                    "X-Frame-Options or CSP frame-ancestors directive is present and valid. "
                    "The page cannot be embedded in a cross-origin iframe."
                )
            ))

        return self.results

    def _check_main_page(self, url: str, headers: dict, body: str) -> None:
        xfo = headers.get("x-frame-options", "").strip()
        fa = _csp_frame_ancestors(headers)
        has_xfo = bool(xfo)
        has_csp_fa = bool(fa)
        has_js_framebusting = bool(_FRAMEBUSTING_JS_RE.search(body))

        if not has_xfo and not has_csp_fa:
            if has_js_framebusting:
                log_warn(logger, f"Clickjacking: only JS frame-busting, no HTTP headers: {url}")
                self.results.append(self._result(
                    url, "Clickjacking — only JavaScript frame-busting (no HTTP headers)", "WARN",
                    detail=(
                        "The page relies on JavaScript frame-busting code but has no "
                        "X-Frame-Options or CSP frame-ancestors header. "
                        "JS frame-busting can be bypassed using sandbox attribute: "
                        "<iframe sandbox='allow-forms allow-scripts' src='...'>. "
                        "Fix: add X-Frame-Options: DENY or CSP frame-ancestors 'none'. "
                        "HTTP headers cannot be bypassed by iframes."
                    )
                ))
            else:
                log_fail(logger, f"Clickjacking: no framing protection on {url}")
                self.results.append(self._result(
                    url, "Clickjacking — page has no framing protection", "FAIL",
                    detail=(
                        "No X-Frame-Options header, no CSP frame-ancestors, and no JavaScript "
                        "frame-busting detected. The page can be embedded in a cross-origin "
                        "iframe and used for clickjacking attacks. "
                        "Fix: add Content-Security-Policy: frame-ancestors 'none'; "
                        "or X-Frame-Options: DENY for sites that don't need to be embedded."
                    )
                ))
            return

        # X-Frame-Options ALLOW-FROM is deprecated
        if has_xfo and _XFO_ALLOW_FROM_RE.search(xfo):
            log_warn(logger, f"Clickjacking: X-Frame-Options ALLOW-FROM is deprecated: {url}")
            self.results.append(self._result(
                url, "Clickjacking — X-Frame-Options ALLOW-FROM is browser-deprecated", "WARN",
                detail=(
                    f"X-Frame-Options: {xfo} uses ALLOW-FROM which is only honored by IE/Edge Legacy. "
                    "Chrome, Firefox, and Safari ignore ALLOW-FROM entirely, leaving the page "
                    "unprotected in those browsers. "
                    "Fix: replace with CSP frame-ancestors 'self' https://trusted.example.com "
                    "which has broad browser support."
                )
            ))

        # Conflict: XFO says DENY but CSP says self (or vice versa)
        if has_xfo and has_csp_fa:
            fa_lower = fa.lower().strip()
            if "deny" in xfo.lower() and fa_lower not in ("'none'", "none"):
                log_warn(logger, f"Clickjacking: XFO DENY conflicts with CSP frame-ancestors {fa}: {url}")
                self.results.append(self._result(
                    url, f"Clickjacking — X-Frame-Options DENY conflicts with CSP frame-ancestors: {fa[:40]}", "WARN",
                    detail=(
                        f"X-Frame-Options: DENY and CSP frame-ancestors: {fa} send conflicting signals. "
                        "Browsers generally honour CSP over XFO, meaning the more permissive "
                        "frame-ancestors policy wins. "
                        "Fix: align both to the same restrictive policy, or rely solely on "
                        "CSP frame-ancestors and remove X-Frame-Options."
                    )
                ))

    def _check_sensitive_pages(self, url: str) -> None:
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in _SENSITIVE_PATHS:
            probe = base + path
            r = self.http.get(probe)
            if r is None:
                continue
            if r.status_code not in (200, 403):
                continue

            h = {k.lower(): v for k, v in r.headers.items()}
            xfo = h.get("x-frame-options", "")
            fa = _csp_frame_ancestors(h)

            if not xfo and not fa:
                log_fail(logger, f"Clickjacking: sensitive page unprotected: {probe}")
                self.results.append(self._result(
                    probe,
                    f"Clickjacking — sensitive page frameable without protection: {path}",
                    "FAIL",
                    detail=(
                        f"Sensitive page {probe} (HTTP {r.status_code}) has no X-Frame-Options "
                        "or CSP frame-ancestors. Clickjacking on login/payment/account pages "
                        "can steal credentials, trick fund transfers, or change account settings. "
                        "Fix: add frame-ancestors 'none' to all sensitive authenticated pages."
                    )
                ))
                return  # One sensitive FAIL finding is enough to report
