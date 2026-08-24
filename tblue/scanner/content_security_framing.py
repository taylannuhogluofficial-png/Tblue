"""Content security framing — frame-ancestors analysis, XFO/CSP interaction, sandboxed iframes."""
import re
from .base import BaseScanner

_XFO_RE = re.compile(r'x-frame-options', re.I)
_XFO_DENY_RE = re.compile(r'\bDENY\b', re.I)
_XFO_SAMEORIGIN_RE = re.compile(r'\bSAMEORIGIN\b', re.I)
_XFO_ALLOWFROM_RE = re.compile(r'\bALLOW-FROM\b', re.I)

_CSP_RE = re.compile(r'content-security-policy', re.I)
_FRAME_ANCESTORS_RE = re.compile(r'frame-ancestors\s+([^;]+)', re.I)
_FRAME_ANCESTORS_NONE_RE = re.compile(r"frame-ancestors\s+'none'", re.I)
_FRAME_ANCESTORS_SELF_RE = re.compile(r"frame-ancestors\s+'self'(?:\s*;|\s*$)", re.I)
_FRAME_ANCESTORS_WILDCARD_RE = re.compile(r'frame-ancestors\s+\*', re.I)

_EMBED_TAG_RE = re.compile(r'<embed\b[^>]*>', re.I)
_OBJECT_TAG_RE = re.compile(r'<object\b[^>]*>', re.I)
_APPLET_TAG_RE = re.compile(r'<applet\b', re.I)


def _get_header(headers, name: str) -> str:
    if hasattr(headers, "get"):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    if isinstance(headers, dict):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    return ""


def _analyze_framing_headers(headers, body: str, url: str) -> list:
    findings = []
    xfo = _get_header(headers, "x-frame-options")
    csp = _get_header(headers, "content-security-policy")

    fa_match = _FRAME_ANCESTORS_RE.search(csp)
    has_xfo = bool(xfo)

    if fa_match and _FRAME_ANCESTORS_WILDCARD_RE.search(csp):
        findings.append({
            "type": "content_security_frame_ancestors_wildcard",
            "status": "FAIL",
            "url": url,
            "detail": "CSP frame-ancestors: * permits any origin to frame this page — clickjacking risk",
        })
        return findings

    if has_xfo and _XFO_ALLOWFROM_RE.search(xfo) and not fa_match:
        findings.append({
            "type": "content_security_xfo_allow_from_no_csp",
            "status": "WARN",
            "url": url,
            "detail": ("X-Frame-Options: ALLOW-FROM is deprecated and not supported in modern browsers; "
                       "no CSP frame-ancestors fallback — page may be frameable in Chrome/Firefox"),
        })

    if has_xfo and fa_match:
        xfo_val = xfo.upper()
        fa_val = fa_match.group(1).strip()
        if ("DENY" in xfo_val or "SAMEORIGIN" in xfo_val) and \
                not ("'none'" in fa_val or "'self'" in fa_val):
            findings.append({
                "type": "content_security_xfo_csp_mismatch",
                "status": "WARN",
                "url": url,
                "detail": (f"X-Frame-Options ({xfo!r}) and CSP frame-ancestors ({fa_val!r}) "
                           f"are inconsistent — browser uses CSP when both present; audit both"),
            })

    if not has_xfo and not fa_match:
        findings.append({
            "type": "content_security_no_framing_protection",
            "status": "FAIL",
            "url": url,
            "detail": "Neither X-Frame-Options nor CSP frame-ancestors present — page is frameable",
        })

    if _APPLET_TAG_RE.search(body):
        findings.append({
            "type": "content_security_applet_tag",
            "status": "WARN",
            "url": url,
            "detail": "<applet> tag detected — Java applets are deprecated and a significant security risk",
        })

    if _OBJECT_TAG_RE.search(body) or _EMBED_TAG_RE.search(body):
        findings.append({
            "type": "content_security_plugin_object",
            "status": "WARN",
            "url": url,
            "detail": "<object>/<embed> tags detected — plugin-based content bypasses CSP and sandbox restrictions",
        })

    return findings


class ContentSecurityFramingScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "content_security_framing_no_response", "PASS",
                                 detail="No response")]

        body = resp.text or ""
        headers = resp.headers

        for f in _analyze_framing_headers(headers, body, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "content_security_framing_protected", "PASS",
                                        detail="Content framing protection appears adequate"))
        return results
