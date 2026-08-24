"""HTTP method override — X-HTTP-Method-Override abuse, CSRF via GET-to-POST override, tunneled DELETE."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_OVERRIDE_HEADERS = [
    "x-http-method-override",
    "x-method-override",
    "x-http-method",
    "_method",
]

_DANGEROUS_METHODS = {"DELETE", "PUT", "PATCH"}

_FORM_METHOD_FIELD_RE = re.compile(
    r'<input\b[^>]*\bname=["\']_method["\'][^>]*\bvalue=["\']([A-Z]+)["\']',
    re.I,
)
_VARY_RE = re.compile(r'\bvary\b', re.I)


def _check_override_headers_reflected(http, url: str) -> list:
    """Send DELETE via X-HTTP-Method-Override to GET endpoint; if 200 → server processes override."""
    findings = []
    for hdr in _OVERRIDE_HEADERS:
        try:
            resp = http.get(url, headers={hdr: "DELETE"})
            if resp and resp.status_code == 200:
                # If the server processed the override, it may return a different body
                # We can only flag that it accepted a dangerous method header without error
                findings.append({
                    "type": "http_method_override_accepted",
                    "status": "WARN",
                    "url": url,
                    "detail": (f"Server accepted {hdr}: DELETE on GET request without rejecting — "
                               f"method override may be processed, enabling CSRF via override"),
                })
                return findings  # one finding per URL is enough
        except Exception:
            pass
    return findings


def _check_form_method_tunneling(body: str, url: str) -> list:
    """Detect HTML forms using _method=DELETE/PUT hidden field (Rails-style override)."""
    findings = []
    for m in _FORM_METHOD_FIELD_RE.finditer(body):
        method = m.group(1).upper()
        if method in _DANGEROUS_METHODS:
            findings.append({
                "type": "http_method_override_form_tunnel",
                "status": "WARN",
                "url": url,
                "detail": (f"Form uses _method={method} hidden field for method tunneling — "
                           f"ensure CSRF protection applies to tunneled {method} requests"),
            })
    return findings


def _check_options_allows_override(http, url: str) -> list:
    """If OPTIONS response includes PATCH/DELETE but GET doesn't, override may enable them."""
    findings = []
    try:
        resp = http.get(url, headers={"X-HTTP-Method-Override": "OPTIONS"})
        if resp and resp.headers:
            allow = resp.headers.get("allow", "") or resp.headers.get("access-control-allow-methods", "")
            if any(m in allow.upper() for m in _DANGEROUS_METHODS):
                if "DELETE" in allow.upper() or "PUT" in allow.upper():
                    findings.append({
                        "type": "http_method_override_dangerous_allowed",
                        "status": "WARN",
                        "url": url,
                        "detail": (f"Allow header exposes dangerous methods: {allow} — "
                                   f"method override tunneling could bypass firewall rules"),
                    })
    except Exception:
        pass
    return findings


class HTTPMethodOverrideScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "http_method_override_no_response", "PASS",
                                 detail="No response")]

        for f in _check_form_method_tunneling(resp.text, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        for f in _check_override_headers_reflected(self.http, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        for f in _check_options_allows_override(self.http, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        if not results:
            results.append(self._result(url, "http_method_override_clean", "PASS",
                                        detail="No HTTP method override issues detected"))
        return results
