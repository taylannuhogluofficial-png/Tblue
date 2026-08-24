"""Clickjacking advanced — frame embedding feasibility, CSP analysis, ALLOW-FROM origin enumeration."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_XFO_RE = re.compile(r'(DENY|SAMEORIGIN|ALLOW-FROM\s+\S+)', re.I)
_ALLOW_FROM_RE = re.compile(r'ALLOW-FROM\s+(\S+)', re.I)
_CSP_FRAME_ANCESTORS_RE = re.compile(r'frame-ancestors\s+([^;]+)', re.I)

_SENSITIVE_PATHS = [
    "/admin", "/account", "/settings", "/profile", "/payment",
    "/checkout", "/transfer", "/dashboard", "/api/user",
]

_CLICKJACKING_JS_BUSTERS_RE = re.compile(
    r'(?:top\s*!?=+\s*self|top\.location|self\.location\s*=|framebusting)',
    re.I,
)


def _analyze_framing_protection(headers: dict, url: str) -> list:
    findings = []
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")

    fa_match = _CSP_FRAME_ANCESTORS_RE.search(csp)
    xfo_match = _XFO_RE.search(xfo)

    if not fa_match and not xfo_match:
        findings.append({
            "type": "clickjacking_no_protection",
            "status": "FAIL",
            "url": url,
            "detail": "No X-Frame-Options or CSP frame-ancestors — page is frameable (clickjacking risk)",
        })
        return findings

    # X-Frame-Options: ALLOW-FROM is deprecated and origin-specific
    allow_from = _ALLOW_FROM_RE.search(xfo)
    if allow_from:
        findings.append({
            "type": "clickjacking_allow_from_deprecated",
            "status": "WARN",
            "url": url,
            "detail": (f"X-Frame-Options: ALLOW-FROM is deprecated and inconsistently supported — "
                       f"use CSP frame-ancestors instead. Allowed: {allow_from.group(1)}"),
        })

    # CSP frame-ancestors: * allows all origins
    if fa_match:
        directive = fa_match.group(1).strip()
        origins = directive.split()
        if "*" in origins:
            findings.append({
                "type": "clickjacking_frame_ancestors_wildcard",
                "status": "FAIL",
                "url": url,
                "detail": "CSP frame-ancestors: * allows all origins to embed the page",
            })
        elif "http:" in directive or any(o.startswith("http://") for o in origins):
            findings.append({
                "type": "clickjacking_frame_ancestors_http_origin",
                "status": "WARN",
                "url": url,
                "detail": f"CSP frame-ancestors includes HTTP (non-HTTPS) origin: {directive[:80]}",
            })

    return findings


def _check_js_framebusting(body: str, url: str) -> list:
    """Check if page uses JS frame-busting instead of headers (weaker protection)."""
    findings = []
    if _CLICKJACKING_JS_BUSTERS_RE.search(body):
        findings.append({
            "type": "clickjacking_js_framebuster_only",
            "status": "WARN",
            "url": url,
            "detail": "JS frame-busting detected (top != self / top.location) — "
                      "JS-based protection can be bypassed via sandbox iframe or CSP; "
                      "use X-Frame-Options or CSP frame-ancestors instead",
        })
    return findings


def _check_sensitive_path_frameable(http, origin: str) -> list:
    findings = []
    for path in _SENSITIVE_PATHS[:3]:
        try:
            r = http.get(origin + path)
            if r and r.status_code == 200:
                headers = dict(r.headers) if r.headers else {}
                xfo = headers.get("x-frame-options", "")
                csp = headers.get("content-security-policy", "")
                fa = _CSP_FRAME_ANCESTORS_RE.search(csp)
                xfo_m = _XFO_RE.search(xfo)
                if not fa and not xfo_m:
                    findings.append({
                        "type": "clickjacking_sensitive_page_frameable",
                        "status": "FAIL",
                        "url": origin + path,
                        "detail": (f"Sensitive page {path} is frameable without X-Frame-Options or "
                                   f"CSP frame-ancestors — high-value clickjacking target"),
                    })
                    return findings
        except Exception:
            pass
    return findings


class ClickjackingAdvancedScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "clickjacking_no_response", "PASS",
                                 detail="No response")]

        headers = dict(resp.headers) if resp.headers else {}

        for f in _analyze_framing_protection(headers, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        for f in _check_js_framebusting(resp.text, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for f in _check_sensitive_path_frameable(self.http, origin):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        if not results:
            results.append(self._result(url, "clickjacking_protected", "PASS",
                                        detail="Clickjacking protection appears adequate"))
        return results
