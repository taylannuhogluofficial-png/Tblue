"""Cross-Origin Resource Policy (CORP) security scanner — passive detection of CORP misconfigurations."""
import re
from .base import BaseScanner

_CORP_ANY_RE = re.compile(
    r'(?:Cross-Origin-Resource-Policy\b|CORP\b|cross-origin\b|same-site\b|same-origin\b|'
    r'mode\s*:\s*["\']no-cors["\']|no-cors\b)',
    re.I,
)

_CORP_HEADER_WEAK_RE = re.compile(
    r'Cross-Origin-Resource-Policy[^;\n]{0,50}cross-origin\b',
    re.I,
)

_CORP_MISSING_ON_SENSITIVE_RE = re.compile(
    r'(?:fetch|XMLHttpRequest|img src|script src)[^;]{0,200}'
    r'(?:api/|token|auth|session|credentials)[^;]{0,100}'
    r'(?:no-cors|mode\s*:\s*["\']no-cors["\'])',
    re.I,
)

_CORP_SPECTRE_GADGET_RE = re.compile(
    r'(?:SharedArrayBuffer|Atomics)[^;]{0,200}'
    r'(?:cross-origin|CORP|same-site)',
    re.I,
)


class CORPSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "corp_not_used", "PASS")]

        body = resp.text
        headers_str = " ".join(f"{k}: {v}" for k, v in (resp.headers or {}).items())
        combined = body + "\n" + headers_str

        if not _CORP_ANY_RE.search(combined):
            return [self._result(url, "corp_not_used", "PASS")]

        findings = []

        if _CORP_HEADER_WEAK_RE.search(combined):
            findings.append(self._result(
                url, "corp_cross_origin_policy", "WARN",
                detail="CORP header set to cross-origin — allows any cross-origin context to embed this resource (Spectre risk).",
            ))

        if _CORP_MISSING_ON_SENSITIVE_RE.search(body):
            findings.append(self._result(
                url, "corp_no_cors_on_auth_resource", "FAIL",
                detail="no-cors mode used to fetch auth/token/session endpoint — bypasses CORP for cross-origin opaque reads.",
            ))

        if _CORP_SPECTRE_GADGET_RE.search(body):
            findings.append(self._result(
                url, "corp_spectre_gadget", "FAIL",
                detail="SharedArrayBuffer/Atomics referenced alongside CORP/cross-origin — Spectre timing gadget in cross-origin isolated context.",
            ))

        return findings or [self._result(url, "corp_safe", "PASS")]
