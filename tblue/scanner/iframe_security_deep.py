"""Iframe security deep — X-Frame-Options, CSP frame-ancestors, sandbox attributes, clickjacking risk."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_IFRAME_RE = re.compile(r'<iframe\b([^>]*)>', re.I | re.S)
_SANDBOX_RE = re.compile(r'\bsandbox\b', re.I)
_SANDBOX_ALLOW_SCRIPTS_RE = re.compile(r'sandbox\s*=\s*["\'][^"\']*allow-scripts[^"\']*["\']', re.I)
_SANDBOX_ALLOW_SAME_ORIGIN_RE = re.compile(r'sandbox\s*=\s*["\'][^"\']*allow-same-origin[^"\']*["\']', re.I)
_SRC_RE = re.compile(r'\bsrc\s*=\s*["\']([^"\']+)["\']', re.I)
_SRCDOC_RE = re.compile(r'\bsrcdoc\b', re.I)

_CSP_FRAME_ANCESTORS_RE = re.compile(r'frame-ancestors\s+([^;]+)', re.I)
_XFO_RE = re.compile(r'(DENY|SAMEORIGIN|ALLOW-FROM)', re.I)


def _check_framing_headers(headers: dict, url: str) -> list:
    findings = []
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")

    fa_match = _CSP_FRAME_ANCESTORS_RE.search(csp)
    has_frame_ancestors = bool(fa_match and fa_match.group(1).strip() not in ("*",))
    has_xfo = bool(_XFO_RE.search(xfo))

    if not has_frame_ancestors and not has_xfo:
        findings.append({
            "type": "iframe_no_framing_protection",
            "status": "FAIL",
            "url": url,
            "detail": "No X-Frame-Options or CSP frame-ancestors — page is embeddable (clickjacking risk)",
        })
    elif fa_match:
        directive = fa_match.group(1).strip()
        if directive == "*":
            findings.append({
                "type": "iframe_csp_frame_ancestors_wildcard",
                "status": "FAIL",
                "url": url,
                "detail": "CSP frame-ancestors: * allows any origin to embed this page (clickjacking)",
            })
    return findings


def _check_iframes_in_page(body: str, page_url: str) -> list:
    findings = []
    parsed = urlparse(page_url)
    page_origin = f"{parsed.scheme}://{parsed.netloc}"

    for m in _IFRAME_RE.finditer(body):
        attrs = m.group(1)
        src_m = _SRC_RE.search(attrs)
        src = src_m.group(1) if src_m else ""

        is_external = src.startswith("http") and not src.startswith(page_origin)
        has_sandbox = bool(_SANDBOX_RE.search(attrs))
        has_scripts = bool(_SANDBOX_ALLOW_SCRIPTS_RE.search(attrs))
        has_same_origin = bool(_SANDBOX_ALLOW_SAME_ORIGIN_RE.search(attrs))

        if is_external and not has_sandbox:
            findings.append({
                "type": "iframe_external_without_sandbox",
                "status": "WARN",
                "url": page_url,
                "detail": f"External iframe src={src[:80]} has no sandbox attribute — "
                           "XSS from embedded page can escape into parent",
            })

        if has_sandbox and has_scripts and has_same_origin:
            findings.append({
                "type": "iframe_sandbox_bypass_combo",
                "status": "WARN",
                "url": page_url,
                "detail": "iframe sandbox has both allow-scripts and allow-same-origin — "
                           "the sandbox can be escaped by script removing the sandbox attribute",
            })

    return findings


class IframeSecurityDeepScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "iframe_no_response", "PASS",
                                 detail="No response")]

        headers = dict(resp.headers) if resp.headers else {}

        for f in _check_framing_headers(headers, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        for f in _check_iframes_in_page(resp.text, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        if not results:
            results.append(self._result(url, "iframe_security_ok", "PASS",
                                        detail="Framing protection and iframe usage looks safe"))
        return results
