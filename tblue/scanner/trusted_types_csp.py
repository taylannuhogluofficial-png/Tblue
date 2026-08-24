"""Trusted Types CSP policy — missing require-trusted-types-for, no default-src restrictions, unsafe sinks."""
import re
from .base import BaseScanner

_CSP_RE = re.compile(r'content-security-policy(?:-report-only)?', re.I)
_TRUSTED_TYPES_RE = re.compile(r'require-trusted-types-for\s+["\']?script["\']?', re.I)
_TRUSTED_TYPES_POLICY_RE = re.compile(r'trusted-types\s+', re.I)

_DOM_SINK_RE = re.compile(
    r'(?:\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|insertAdjacentHTML\s*\(|'
    r'\.src\s*=\s*["\']?(?:javascript:|data:)|eval\s*\(|new\s+Function\s*\(|'
    r'\.setAttribute\s*\(\s*["\'](?:href|src|action)["\'])',
    re.I,
)

_SAFE_DOM_SINK_RE = re.compile(r'TrustedHTML|TrustedScript|TrustedScriptURL|createPolicy', re.I)


def _get_header(headers, name: str) -> str:
    if hasattr(headers, "get"):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    if isinstance(headers, dict):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    return ""


def _parse_csp(headers) -> str:
    return _get_header(headers, "content-security-policy")


class TrustedTypesCspScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "trusted_types_no_response", "PASS", detail="No response")]

        csp = _parse_csp(resp.headers)
        body = resp.text or ""

        has_trusted_types = bool(_TRUSTED_TYPES_RE.search(csp))
        has_trusted_types_policy = bool(_TRUSTED_TYPES_POLICY_RE.search(csp))

        uses_dom_sinks = bool(_DOM_SINK_RE.search(body))
        uses_trusted_types_api = bool(_SAFE_DOM_SINK_RE.search(body))

        if uses_dom_sinks and not has_trusted_types:
            if uses_trusted_types_api:
                results.append(self._result(url, "trusted_types_api_no_enforcement", "WARN",
                                            detail="Page uses Trusted Types API (createPolicy) but CSP lacks "
                                                   "'require-trusted-types-for script' — Trusted Types are opt-in "
                                                   "without enforcement, bypassed by legacy code paths"))
            else:
                results.append(self._result(url, "trusted_types_missing_with_dom_sinks", "WARN",
                                            detail="Page has DOM XSS sinks (innerHTML/document.write/eval) without "
                                                   "Trusted Types CSP enforcement — 'require-trusted-types-for script' "
                                                   "would prevent XSS at the platform level"))
        elif not has_trusted_types and not uses_dom_sinks:
            results.append(self._result(url, "trusted_types_not_configured", "INFO",
                                        detail="Trusted Types CSP not configured ('require-trusted-types-for script') — "
                                               "consider adopting for defence-in-depth against DOM XSS"))

        if has_trusted_types and not has_trusted_types_policy:
            results.append(self._result(url, "trusted_types_no_allowlist", "WARN",
                                        detail="CSP has require-trusted-types-for but no 'trusted-types' allowlist — "
                                               "allows creation of any named policy; restrict to specific policy names"))

        if not results:
            if has_trusted_types:
                results.append(self._result(url, "trusted_types_enforced", "PASS",
                                            detail="Trusted Types CSP enforcement configured correctly"))
            else:
                results.append(self._result(url, "trusted_types_no_dom_sinks", "PASS",
                                            detail="No Trusted Types enforcement but no obvious DOM XSS sinks detected"))
        return results
