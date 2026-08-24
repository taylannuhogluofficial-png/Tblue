"""
Document-Policy Security Scanner.

Document-Policy is a W3C specification that allows web pages to opt into
or restrict browser behaviors on a per-document basis. It complements
Permissions-Policy (which applies to APIs) by controlling document-level
behaviors affecting security and performance.

Checks:

1. Missing `no-document-write` — disabling document.write() removes a
   common DOM XSS sink exploited by script injection via document.write.
2. Missing `sync-xhr` policy — synchronous XHR (XMLHttpRequest) blocks
   the main thread and is a performance denial-of-service vector; can also
   be exploited to block rendering during attacks.
3. Missing `allow-downloads` / `allow-downloads-without-user-activation`:
   - Without this restriction, any script can trigger file downloads without
     user interaction, enabling drive-by-download attacks.
4. `Require-Document-Policy` response header:
   - When present, enforces the policy on embedded documents (iframes).
   - Missing this enforcement allows embedded content to bypass document policies.
5. Document-Policy in report-only mode without enforcement:
   - Policy is logged but not enforced — same false-security as CSP-RO.
6. `js-profiling` enabled — allows JavaScript profiling access, which can
   be used for timing oracle attacks.

Reference: https://wicg.github.io/document-policy/
CWE-693: Protection Mechanism Failure
"""

import re
from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_FEATURE_RE = re.compile(r'([a-z][a-z0-9-]*)(?:\s*=\s*(\?[01]|[^,;]+))?', re.I)

_SECURITY_FEATURES = {
    "no-document-write": {
        "expected": "?1",
        "severity": "WARN",
        "cve_hint": "",
        "detail": (
            "Document-Policy should include 'no-document-write' (or 'document-write=?0') "
            "to disable document.write(). This DOM API is a known XSS sink exploited in "
            "DOM-based script injection attacks. "
            "Fix: add 'no-document-write' to the Document-Policy header."
        ),
    },
    "sync-xhr": {
        "expected": "?0",
        "severity": "WARN",
        "detail": (
            "Document-Policy should restrict 'sync-xhr' to prevent synchronous "
            "XMLHttpRequest, which blocks the main thread and enables denial-of-service "
            "via layout thrashing. "
            "Fix: add 'sync-xhr=?0' to Document-Policy."
        ),
    },
    "allow-downloads-without-user-activation": {
        "expected": "?0",
        "severity": "WARN",
        "detail": (
            "Document-Policy should restrict downloads without user activation. "
            "Without this, scripts can trigger file downloads without user interaction, "
            "enabling drive-by-download attacks. "
            "Fix: add 'allow-downloads-without-user-activation=?0' to Document-Policy."
        ),
    },
}

_HIGH_RISK_FEATURES = {
    "js-profiling": (
        "Document-Policy enables 'js-profiling', allowing JavaScript profiling access "
        "which can be used for timing oracle attacks. "
        "Fix: remove 'js-profiling' from Document-Policy unless required for developer tools."
    ),
    "force-load-at-top": None,
}


class DocumentPolicySecurityScanner(BaseScanner):
    """Detect missing or weak Document-Policy header configuration."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "Document-Policy — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        h = resp.headers
        dp_header    = h.get("document-policy", "")
        dp_ro_header = h.get("document-policy-report-only", "")
        req_dp       = h.get("require-document-policy", "")

        if not dp_header and not dp_ro_header:
            log_pass(logger, f"No Document-Policy header at {url}")
            self.results.append(self._result(
                url, "Document-Policy — header not present", "PASS",
                detail=(
                    "Document-Policy is not set. This is a newer header (Chrome 74+) that "
                    "controls document-level behaviors. Consider adopting it to restrict "
                    "no-document-write, sync-xhr, and drive-by downloads."
                )
            ))
            return self.results

        if dp_ro_header and not dp_header:
            log_warn(logger, f"Document-Policy in report-only mode only at {url}")
            self.results.append(self._result(
                url, "Document-Policy — report-only only (not enforcing)", "WARN",
                detail=(
                    "Document-Policy-Report-Only is set but the enforcing Document-Policy "
                    "header is absent. Policy violations are logged but not blocked. "
                    "Fix: migrate the policy to the enforcing Document-Policy header."
                )
            ))
            return self.results

        parsed_features = self._parse_policy(dp_header)

        self._check_dangerous_features(url, parsed_features, dp_header)
        self._check_require_doc_policy(url, req_dp, dp_header)

        if not any(r["status"] in ("FAIL", "WARN") for r in self.results):
            log_pass(logger, f"Document-Policy is present and configured at {url}")
            self.results.append(self._result(
                url, "Document-Policy — header present and no dangerous features", "PASS",
                detail=f"Document-Policy: {dp_header[:120]}. No high-risk features detected."
            ))

        return self.results

    def _parse_policy(self, policy: str) -> Dict[str, str]:
        features: Dict[str, str] = {}
        for m in _FEATURE_RE.finditer(policy):
            name = m.group(1).lower()
            val  = (m.group(2) or "?1").strip()
            features[name] = val
        return features

    def _check_dangerous_features(
        self, url: str, features: Dict[str, str], dp_raw: str
    ) -> None:
        for feature, detail_text in _HIGH_RISK_FEATURES.items():
            if feature in features and detail_text:
                log_warn(logger, f"Document-Policy dangerous feature {feature} at {url}")
                self.results.append(self._result(
                    url,
                    f"Document-Policy — dangerous feature enabled: {feature}",
                    "WARN",
                    detail=detail_text
                ))

    def _check_require_doc_policy(
        self, url: str, req_dp: str, dp_header: str
    ) -> None:
        if dp_header and not req_dp:
            self.results.append(self._result(
                url,
                "Document-Policy — Require-Document-Policy header missing",
                "WARN",
                detail=(
                    "Document-Policy is set but Require-Document-Policy is absent. "
                    "Without Require-Document-Policy, embedded iframes on this page "
                    "are not required to adopt the same policy. "
                    "Fix: add 'Require-Document-Policy: <policy>' to enforce the policy "
                    "on all embedded documents."
                )
            ))
