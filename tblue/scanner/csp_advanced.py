"""
Advanced Content-Security-Policy scanner.

Goes beyond "CSP present/missing" to analyze:
- report-uri / report-to endpoint configured (CSP violations are silent without it)
- frame-ancestors directive (blocks clickjacking — supersedes X-Frame-Options)
- Trusted Types enforcement (prevents DOM XSS)
- CSP via <meta> tag instead of header (weaker — no report-uri, blocks some directives)
- Upgrade-insecure-requests directive
- base-uri restriction (prevents base tag injection)
- form-action restriction (prevents form hijacking)
"""

import re
from typing import List, Dict, Any, Optional

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_CSP_HEADER      = "Content-Security-Policy"
_CSPR_HEADER     = "Content-Security-Policy-Report-Only"

# Known CDN hosts serving JSONP or AngularJS — bypass CSP if whitelisted
_BYPASS_HOSTS = frozenset({
    "ajax.googleapis.com",
    "ajax.aspnetcdn.com",
    "cdn.jsdelivr.net",
    "code.jquery.com",
    "cdnjs.cloudflare.com",
    "unpkg.com",
    "accounts.google.com",
})


def _parse_directives(csp: str) -> Dict[str, str]:
    directives = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split(None, 1)
        key    = tokens[0].lower()
        value  = tokens[1] if len(tokens) > 1 else ""
        directives[key] = value
    return directives


class CSPAdvancedScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        try:
            resp = self.http.get(url)
            if resp is None:
                return self.results
        except Exception:
            return self.results

        csp_header = resp.headers.get(_CSP_HEADER, "")
        csp_ro     = resp.headers.get(_CSPR_HEADER, "")
        html       = resp.text or ""

        # Detect CSP delivered via <meta> tag
        meta_csp   = self._find_meta_csp(html)

        if not csp_header and not csp_ro:
            if meta_csp:
                log_warn(logger, "CSP delivered via <meta> tag only — weaker than header")
                self.results.append(self._result(url,
                    "CSP advanced — delivered via <meta> tag (weaker than HTTP header)",
                    "WARN",
                    detail=(
                        "CSP is set via a <meta http-equiv> tag instead of the Content-Security-Policy "
                        "HTTP header. Meta-CSP cannot use report-uri, frame-ancestors, or sandbox "
                        "directives. Fix: move CSP to the HTTP header."
                    )))
                csp_header = meta_csp
            else:
                return self.results  # Basic CSP scanner already flags missing CSP

        active_csp = csp_header or csp_ro
        is_ro      = bool(csp_ro and not csp_header)
        directives = _parse_directives(active_csp)

        if is_ro:
            log_warn(logger, "CSP is Report-Only — not enforced")
            self.results.append(self._result(url,
                "CSP advanced — Report-Only mode (not enforced)",
                "WARN",
                detail=(
                    "Content-Security-Policy-Report-Only is set but not Content-Security-Policy. "
                    "Report-Only logs violations but does not block anything — attackers can still "
                    "run injected scripts. Fix: promote to enforced CSP once violations are resolved."
                )))

        self._check_report_endpoint(directives, url)
        self._check_frame_ancestors(directives, url)
        self._check_base_uri(directives, url)
        self._check_form_action(directives, url)
        self._check_upgrade_insecure(directives, url)
        self._check_trusted_types(directives, url)
        self._check_script_src_bypasses(directives, url)
        return self.results

    def _find_meta_csp(self, html: str) -> Optional[str]:
        m = re.search(
            r'<meta\s[^>]*http-equiv=["\']Content-Security-Policy["\'][^>]*content=["\']([^"\']+)["\']',
            html, re.I
        ) or re.search(
            r'<meta\s[^>]*content=["\']([^"\']+)["\'][^>]*http-equiv=["\']Content-Security-Policy["\']',
            html, re.I
        )
        return m.group(1) if m else None

    def _check_report_endpoint(self, directives: Dict[str, str], url: str) -> None:
        has_report_uri = "report-uri" in directives
        has_report_to  = "report-to" in directives
        if has_report_uri or has_report_to:
            endpoint = directives.get("report-uri") or directives.get("report-to", "")
            log_pass(logger, f"CSP report endpoint configured: {endpoint[:60]}")
            self.results.append(self._result(url,
                "CSP advanced — violation reporting configured",
                "PASS",
                detail=(
                    f"CSP has a {'report-uri' if has_report_uri else 'report-to'} directive. "
                    "CSP violations will be reported, enabling detection of injection attempts."
                )))
        else:
            log_warn(logger, "CSP has no report-uri or report-to — violations are silent")
            self.results.append(self._result(url,
                "CSP advanced — no violation reporting (report-uri/report-to missing)",
                "WARN",
                detail=(
                    "CSP has no report-uri or report-to directive. "
                    "When CSP blocks a resource or injection attempt, you receive no notification. "
                    "Fix: add report-to with a reporting endpoint (e.g. report-uri.com, "
                    "sentry.io/security/, or your own collector). "
                    "Violation reports are essential for detecting active attacks."
                )))

    def _check_frame_ancestors(self, directives: Dict[str, str], url: str) -> None:
        if "frame-ancestors" in directives:
            value = directives["frame-ancestors"].strip()
            if value == "'none'":
                log_pass(logger, "frame-ancestors 'none' — clickjacking fully blocked")
                self.results.append(self._result(url,
                    "CSP advanced — frame-ancestors 'none' (clickjacking blocked)",
                    "PASS",
                    detail="CSP frame-ancestors 'none' prevents the page from being embedded in "
                           "any frame or iframe. This is the strongest clickjacking protection."))
            elif value == "'self'":
                log_pass(logger, "frame-ancestors 'self' — only same-origin framing allowed")
                self.results.append(self._result(url,
                    "CSP advanced — frame-ancestors 'self'",
                    "PASS",
                    detail="CSP frame-ancestors 'self' allows the page to be framed only by "
                           "same-origin pages. Third-party clickjacking is blocked."))
            else:
                log_warn(logger, f"frame-ancestors set to: {value[:60]}")
                self.results.append(self._result(url,
                    "CSP advanced — frame-ancestors allows specific origins",
                    "PASS",
                    detail=f"CSP frame-ancestors set to: {value[:80]}. "
                           "Verify these are all trusted origins that should be able to embed this page."))
        else:
            log_warn(logger, "CSP missing frame-ancestors — falls back to X-Frame-Options")
            self.results.append(self._result(url,
                "CSP advanced — frame-ancestors directive missing",
                "WARN",
                detail=(
                    "CSP has no frame-ancestors directive. This means the page relies on "
                    "X-Frame-Options for clickjacking protection. frame-ancestors supersedes "
                    "X-Frame-Options in modern browsers and is the recommended approach. "
                    "Fix: add 'frame-ancestors 'none'' or 'frame-ancestors 'self'' to CSP."
                )))

    def _check_base_uri(self, directives: Dict[str, str], url: str) -> None:
        if "base-uri" in directives:
            log_pass(logger, "CSP base-uri configured")
            self.results.append(self._result(url,
                "CSP advanced — base-uri restriction configured",
                "PASS",
                detail=f"CSP base-uri is set to: {directives['base-uri'][:60]}. "
                       "Base tag injection attacks are prevented."))
        else:
            log_warn(logger, "CSP missing base-uri")
            self.results.append(self._result(url,
                "CSP advanced — base-uri not restricted",
                "WARN",
                detail=(
                    "CSP has no base-uri directive. An XSS attacker could inject a <base> tag "
                    "to redirect all relative URLs to an attacker-controlled server. "
                    "Fix: add 'base-uri 'self'' or 'base-uri 'none'' to CSP."
                )))

    def _check_form_action(self, directives: Dict[str, str], url: str) -> None:
        if "form-action" in directives:
            log_pass(logger, "CSP form-action configured")
            self.results.append(self._result(url,
                "CSP advanced — form-action restriction configured",
                "PASS",
                detail=f"CSP form-action is set to: {directives['form-action'][:60]}. "
                       "Forms cannot be hijacked to submit data to external servers."))
        else:
            log_warn(logger, "CSP missing form-action")
            self.results.append(self._result(url,
                "CSP advanced — form-action not restricted",
                "WARN",
                detail=(
                    "CSP has no form-action directive. An XSS attacker could modify form "
                    "action attributes to exfiltrate user-submitted data to an external server. "
                    "Fix: add 'form-action 'self'' to restrict where forms can submit."
                )))

    def _check_upgrade_insecure(self, directives: Dict[str, str], url: str) -> None:
        if "upgrade-insecure-requests" in directives:
            log_pass(logger, "CSP upgrade-insecure-requests present")
            self.results.append(self._result(url,
                "CSP advanced — upgrade-insecure-requests configured",
                "PASS",
                detail="CSP upgrade-insecure-requests automatically upgrades HTTP sub-resources "
                       "to HTTPS, preventing mixed content issues on legacy pages."))

    def _check_trusted_types(self, directives: Dict[str, str], url: str) -> None:
        if "require-trusted-types-for" in directives:
            log_pass(logger, "Trusted Types enforced")
            self.results.append(self._result(url,
                "CSP advanced — Trusted Types enforced (DOM XSS prevention)",
                "PASS",
                detail="require-trusted-types-for 'script' is configured. "
                       "This prevents DOM XSS by requiring all dangerous DOM sinks "
                       "(innerHTML, document.write, etc.) to receive sanitized Trusted Type objects."))

    def _check_script_src_bypasses(self, directives: Dict[str, str], url: str) -> None:
        """Check for known CSP bypass vectors in script-src / default-src."""
        src_value = directives.get("script-src") or directives.get("default-src") or ""

        if "'unsafe-inline'" in src_value:
            log_fail(logger, f"CSP 'unsafe-inline' in script-src: {url}")
            self.results.append(self._result(url,
                "CSP advanced — 'unsafe-inline' in script-src (XSS protection bypassed)", "FAIL",
                detail=(
                    "'unsafe-inline' in script-src completely disables inline script blocking. "
                    "Any injected <script>...</script> or on* attribute handler executes freely. "
                    "Fix: remove 'unsafe-inline'; use per-script nonces (script-src 'nonce-{random}') "
                    "or hash-based whitelisting instead."
                )))

        if "'unsafe-eval'" in src_value:
            log_warn(logger, f"CSP 'unsafe-eval' in script-src: {url}")
            self.results.append(self._result(url,
                "CSP advanced — 'unsafe-eval' in script-src", "WARN",
                detail=(
                    "'unsafe-eval' allows eval(), new Function(), setTimeout(string), and "
                    "setInterval(string). If any user-controlled data reaches these sinks, "
                    "DOM-based XSS is possible even without a full CSP bypass. "
                    "Fix: rewrite code to avoid eval(); use JSON.parse() instead of eval()."
                )))

        if re.search(r"(?:^|\s)\*(?:\s|$)", src_value):
            log_fail(logger, f"CSP wildcard (*) in script-src: {url}")
            self.results.append(self._result(url,
                "CSP advanced — wildcard (*) in script-src (allows scripts from any host)", "FAIL",
                detail=(
                    "A wildcard (*) in script-src permits scripts from any domain, "
                    "rendering the directive useless. Fix: list specific trusted hosts explicitly."
                )))

        if re.search(r"(?:^|\s)data:", src_value):
            log_fail(logger, f"CSP data: URI in script-src: {url}")
            self.results.append(self._result(url,
                "CSP advanced — data: URI in script-src", "FAIL",
                detail=(
                    "data: in script-src allows <script src='data:text/javascript,...'>. "
                    "This is a well-known bypass for XSS filters. "
                    "Fix: remove data: from script-src."
                )))

        bypass_found = [h for h in _BYPASS_HOSTS if h in src_value]
        if bypass_found:
            log_warn(logger, f"CSP script-src includes known JSONP bypass host: {bypass_found}")
            self.results.append(self._result(url,
                f"CSP advanced — JSONP/AngularJS bypass host in script-src: {bypass_found[:2]}", "WARN",
                detail=(
                    f"script-src whitelists {bypass_found}, which hosts JSONP endpoints or "
                    "legacy AngularJS — both allow arbitrary script execution via CSP-allowed URLs. "
                    "Fix: remove these CDN hosts from script-src; use file hashes or self-host assets."
                )))
