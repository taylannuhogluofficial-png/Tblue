"""
Speculation Rules Security Scanner.

The Speculation Rules API (Chrome 109+) enables browsers to prerender
or prefetch pages based on JSON rules declared in-page or via HTTP headers.
Security implications:

1. Sensitive URL prefetching — speculation rules that target auth/admin/
   payment URLs may cause browsers to issue credentialed prefetch requests
   to sensitive pages, potentially triggering side effects.
2. Open-ended rules — catch-all patterns (href_matches: '*') cause
   browsers to speculatively load ALL links, including logout, delete,
   or state-change endpoints (GET-based CSRF risk).
3. Wildcard rules on subdomains — cross-origin speculative loads bypass
   same-origin restrictions for prefetch (not prerender) in some browsers.
4. Exposed Speculation-Rules HTTP header — server reveals which URLs are
   high-priority targets, giving attackers a roadmap.
5. No-Vary-Search header conflicts — speculation rules combined with
   no-vary-search cache directives may cause cache poisoning.

Reference: https://developer.chrome.com/blog/speculation-rules/
CWE-200: Exposure of Sensitive Information
CWE-352: Cross-Site Request Forgery (for GET-based state change prefetch)
"""

import json
import re
from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_SPEC_RULES_SCRIPT_RE = re.compile(
    r'<script[^>]+type\s*=\s*["\']speculationrules["\'][^>]*>(.*?)</script>',
    re.I | re.S
)
_SENSITIVE_PATHS_RE = re.compile(
    r'/(?:admin|login|logout|signout|auth|checkout|payment|pay|account'
    r'|delete|remove|reset|password|profile/edit|settings|api/)',
    re.I
)
_WILDCARD_HREF_RE = re.compile(
    r'"href_matches"\s*:\s*["\']?\*["\']?'
    r'|"where"\s*:\s*\{[^}]*"href_matches"\s*:\s*["\']?\*["\']?',
    re.I
)
_CROSS_ORIGIN_RE = re.compile(r'"requires"\s*:\s*\[[^\]]*"anonymous-client-ip-when-cross-origin"', re.I)


class SpeculationRulesSecurityScanner(BaseScanner):
    """Detect security issues in Speculation Rules API usage."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "Speculation Rules — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        body = resp.text or ""
        spec_header = resp.headers.get("speculation-rules", "")

        self._check_header_exposure(url, spec_header)
        self._check_inline_rules(url, body)
        self._check_combined_no_vary_search(url, resp.headers)

        if not self.results:
            log_pass(logger, f"No Speculation Rules security issues at {url}")
            self.results.append(self._result(
                url, "Speculation Rules — not used or no security issues detected", "PASS",
                detail=(
                    "No Speculation-Rules header or inline <script type='speculationrules'> "
                    "found, or rules are safely scoped."
                )
            ))

        return self.results

    def _check_header_exposure(self, url: str, header: str) -> None:
        if not header:
            return

        log_warn(logger, f"Speculation-Rules header exposes URL map at {url}")
        self.results.append(self._result(
            url, "Speculation Rules — HTTP header reveals speculative URL targets", "WARN",
            detail=(
                f"The Speculation-Rules HTTP header is present, pointing to a speculation "
                f"rules document: '{header[:200]}'. This reveals which pages are considered "
                "high-priority by the server, providing attackers with a partial site map. "
                "Consider serving speculation rules only via inline <script> to reduce "
                "header-level information exposure."
            )
        ))

    def _check_inline_rules(self, url: str, body: str) -> None:
        matches = _SPEC_RULES_SCRIPT_RE.findall(body)
        if not matches:
            return

        for rules_json in matches:
            self._analyze_rules_json(url, rules_json.strip())

    def _analyze_rules_json(self, url: str, rules_json: str) -> None:
        try:
            rules = json.loads(rules_json)
        except (json.JSONDecodeError, ValueError):
            return

        actions = []
        for action_type in ("prefetch", "prerender"):
            for entry in rules.get(action_type, []):
                urls = entry.get("urls", [])
                where = entry.get("where", {})
                actions.append((action_type, entry, urls, where))

        if not actions:
            return

        all_urls_text = rules_json

        if _WILDCARD_HREF_RE.search(all_urls_text):
            log_warn(logger, f"Speculation rules wildcard href_matches at {url}")
            self.results.append(self._result(
                url, "Speculation Rules — wildcard href_matches may prefetch sensitive URLs", "WARN",
                detail=(
                    "Speculation rules use a wildcard ('*') href_matches pattern, causing "
                    "the browser to speculatively prefetch or prerender ALL matching links. "
                    "This includes state-change GET endpoints (logout, delete) and private "
                    "pages, potentially triggering side effects or leaking auth responses. "
                    "Fix: scope speculation rules to specific safe URL prefixes (e.g., '/blog/')."
                )
            ))

        if _SENSITIVE_PATHS_RE.search(all_urls_text):
            log_fail(logger, f"Speculation rules targets sensitive paths at {url}")
            self.results.append(self._result(
                url, "Speculation Rules — sensitive paths included in speculative targets", "FAIL",
                detail=(
                    "Speculation rules include URLs matching sensitive path patterns "
                    "(admin, login, logout, checkout, payment, delete, etc.). "
                    "Speculative prefetch sends credentialed requests to these URLs as the "
                    "user browses, potentially triggering logout, state changes, or exposing "
                    "auth redirects to the browser's internal prefetch log. "
                    "Fix: exclude sensitive paths from speculation rules."
                )
            ))

        for action_type, entry, urls, where in actions:
            eagerness = entry.get("eagerness", "")
            if eagerness in ("eager", "immediate") and action_type == "prerender":
                log_warn(logger, f"Eager/immediate prerender in speculation rules at {url}")
                self.results.append(self._result(
                    url, f"Speculation Rules — eagerness={eagerness} prerender (aggressive)", "WARN",
                    detail=(
                        f"Speculation rules include prerender entries with eagerness='{eagerness}'. "
                        "Immediate/eager prerender loads pages in a hidden browsing context "
                        "as soon as the rules are parsed, before user interaction. "
                        "This executes page scripts and fires analytics beacons for pages "
                        "the user never visits. Fix: use 'moderate' or 'conservative' eagerness."
                    )
                ))
                break

    def _check_combined_no_vary_search(self, url: str, h) -> None:
        has_spec = h.get("speculation-rules", "")
        has_nvs  = h.get("no-vary-search", "")
        if has_spec and has_nvs:
            log_warn(logger, f"Speculation-Rules + No-Vary-Search combo at {url}")
            self.results.append(self._result(
                url, "Speculation Rules — combined with No-Vary-Search (cache confusion risk)", "WARN",
                detail=(
                    "Both Speculation-Rules and No-Vary-Search headers are present. "
                    "No-Vary-Search tells the browser to treat different query strings as "
                    "equivalent cache entries. Combined with speculation rules, this can "
                    "cause the browser to serve a cached speculative response to a different "
                    "URL than intended, potentially enabling cache confusion attacks. "
                    "Fix: verify that No-Vary-Search scoping does not overlap with "
                    "security-sensitive URL parameters."
                )
            ))
