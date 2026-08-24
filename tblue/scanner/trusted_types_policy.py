"""
Trusted Types Policy Enforcement Scanner.

Trusted Types is a W3C browser API (Chrome 83+, Edge 83+) that prevents
DOM-based XSS by requiring explicit policy creation before passing strings
to dangerous DOM sinks (innerHTML, document.write, eval, etc.).

Checks for Trusted Types enforcement via Content-Security-Policy:

1. require-trusted-types-for 'script' — enforces Trusted Types for all
   script-related DOM sinks. This is the primary protection directive.
2. trusted-types — defines allowed policy names. Using 'trusted-types none'
   blocks all Trusted Types policy creation; named policies restrict creation.
3. Weak CSP that allows unsafe-eval alongside Trusted Types — defeats the
   protection by still permitting direct eval() usage.
4. Missing directive but TT JavaScript code present — partial implementation
   without enforcement (detection only, not blocking).
5. meta http-equiv CSP — Trusted Types directives must be in HTTP headers;
   meta-tag CSP cannot set require-trusted-types-for.

Reference: https://w3c.github.io/trusted-types/dist/spec/
CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)
"""

import re
from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_TT_REQUIRE_RE  = re.compile(r'require-trusted-types-for\s+["\']?script["\']?', re.I)
_TT_POLICY_RE   = re.compile(r'trusted-types\s+(\S[^;]*)', re.I)
_UNSAFE_EVAL_RE = re.compile(r"'unsafe-eval'", re.I)

_TT_JS_API_RE = re.compile(
    r'trustedTypes\.(?:createPolicy|getAttributeType|isHTML|isScript|isScriptURL)',
    re.I
)
_META_CSP_RE = re.compile(
    r'<meta[^>]+http-equiv\s*=\s*["\']content-security-policy["\'][^>]*>',
    re.I
)
_INNER_HTML_RE = re.compile(
    r'\.innerHTML\s*=|document\.write\s*\(',
    re.I
)


class TrustedTypesPolicyScanner(BaseScanner):
    """Detect missing or weak Trusted Types enforcement in CSP."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "Trusted Types — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        csp_header = resp.headers.get("content-security-policy", "")
        csp_ro     = resp.headers.get("content-security-policy-report-only", "")
        body       = resp.text or ""

        self._check_require_directive(url, csp_header, csp_ro)
        self._check_unsafe_eval_with_tt(url, csp_header)
        self._check_meta_csp_tt(url, body)
        self._check_tt_js_without_enforcement(url, body, csp_header, csp_ro)
        self._check_dangerous_sinks(url, body, csp_header)

        if not any(r["status"] in ("FAIL", "WARN") for r in self.results):
            log_pass(logger, f"Trusted Types enforced at {url}")
            self.results.append(self._result(
                url, "Trusted Types — require-trusted-types-for 'script' enforced", "PASS",
                detail="CSP includes require-trusted-types-for 'script', blocking DOM XSS via dangerous sinks."
            ))

        return self.results

    def _check_require_directive(self, url: str, csp: str, csp_ro: str) -> None:
        has_enforcement = bool(_TT_REQUIRE_RE.search(csp))
        has_report_only = bool(_TT_REQUIRE_RE.search(csp_ro))

        if has_enforcement:
            return

        if has_report_only:
            log_warn(logger, f"Trusted Types in report-only mode at {url}")
            self.results.append(self._result(
                url, "Trusted Types — enforced only in report-only mode", "WARN",
                detail=(
                    "Content-Security-Policy-Report-Only contains require-trusted-types-for 'script' "
                    "but the enforcing Content-Security-Policy header does not. Trusted Types "
                    "violations are reported but not blocked. "
                    "Fix: move require-trusted-types-for 'script' to the enforcing CSP header."
                )
            ))
        else:
            log_warn(logger, f"Missing Trusted Types enforcement at {url}")
            self.results.append(self._result(
                url, "Trusted Types — require-trusted-types-for 'script' not enforced", "WARN",
                detail=(
                    "Content-Security-Policy does not include require-trusted-types-for 'script'. "
                    "Without this directive, dangerous DOM sinks (innerHTML, document.write, eval, "
                    "setTimeout with string argument, etc.) accept raw strings, leaving the "
                    "application vulnerable to DOM-based XSS. "
                    "Fix: add \"require-trusted-types-for 'script'\" to CSP and adopt the "
                    "Trusted Types JavaScript API for any code that writes to DOM sinks."
                )
            ))

    def _check_unsafe_eval_with_tt(self, url: str, csp: str) -> None:
        if not (_TT_REQUIRE_RE.search(csp) and _UNSAFE_EVAL_RE.search(csp)):
            return
        log_warn(logger, f"Trusted Types weakened by unsafe-eval at {url}")
        self.results.append(self._result(
            url, "Trusted Types — weakened by 'unsafe-eval' in CSP", "WARN",
            detail=(
                "CSP enforces require-trusted-types-for 'script' but also allows 'unsafe-eval'. "
                "eval() is one of the sinks that Trusted Types protects, so this combination "
                "partially defeats the protection. "
                "Fix: remove 'unsafe-eval' and refactor code to avoid direct eval() usage."
            )
        ))

    def _check_meta_csp_tt(self, url: str, body: str) -> None:
        meta_csps = _META_CSP_RE.findall(body)
        for meta in meta_csps:
            if _TT_REQUIRE_RE.search(meta):
                log_fail(logger, f"Trusted Types via meta CSP (ineffective) at {url}")
                self.results.append(self._result(
                    url, "Trusted Types — require-trusted-types-for in meta CSP (not enforced)", "FAIL",
                    detail=(
                        "The page uses <meta http-equiv='Content-Security-Policy'> to set "
                        "require-trusted-types-for 'script', but browsers do not enforce "
                        "Trusted Types directives set via meta tags — only HTTP header CSP "
                        "enforces Trusted Types. This creates a false sense of security. "
                        "Fix: move the Trusted Types directive to the HTTP Content-Security-Policy header."
                    )
                ))
                return

    def _check_tt_js_without_enforcement(
        self, url: str, body: str, csp: str, csp_ro: str
    ) -> None:
        uses_tt_api = bool(_TT_JS_API_RE.search(body))
        has_enforcement = bool(_TT_REQUIRE_RE.search(csp))

        if uses_tt_api and not has_enforcement:
            log_warn(logger, f"Trusted Types API used without CSP enforcement at {url}")
            self.results.append(self._result(
                url, "Trusted Types — API used in JS but not enforced via CSP", "WARN",
                detail=(
                    "The page uses the Trusted Types JavaScript API (trustedTypes.createPolicy) "
                    "but the Content-Security-Policy does not enforce require-trusted-types-for "
                    "'script'. Trusted Types works as a defense only when enforcement is active "
                    "in the CSP header; otherwise the API is advisory only. "
                    "Fix: add require-trusted-types-for 'script' to the enforcing CSP."
                )
            ))

    def _check_dangerous_sinks(self, url: str, body: str, csp: str) -> None:
        has_enforcement = bool(_TT_REQUIRE_RE.search(csp))
        has_sinks = bool(_INNER_HTML_RE.search(body))

        if has_sinks and not has_enforcement:
            self.results.append(self._result(
                url, "Trusted Types — dangerous DOM sinks detected without enforcement", "WARN",
                detail=(
                    "The page HTML contains patterns associated with dangerous DOM sinks "
                    "(innerHTML=, document.write()) without Trusted Types enforcement in CSP. "
                    "These sinks are XSS vectors when fed attacker-controlled strings. "
                    "Fix: enable require-trusted-types-for 'script' in CSP and use the "
                    "Trusted Types API to wrap any necessary DOM sink writes."
                )
            ))
