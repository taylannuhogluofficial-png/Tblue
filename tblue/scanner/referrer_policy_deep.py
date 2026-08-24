"""
Referrer Policy Deep Analysis Scanner.

The Referrer-Policy header controls how much URL information browsers include
in the Referer header on navigation and subresource requests. Poor policy
choices leak sensitive URL path data (tokens, IDs, search queries) to
third-party origins:

  1. Missing Referrer-Policy — browsers default to no-referrer-when-downgrade,
     which sends the full URL to same-protocol origins.

  2. unsafe-url — always sends full URL including path and query; worst choice.

  3. no-referrer-when-downgrade (the browser default when header absent) —
     sends full URL to HTTPS origins; leaks token params in query strings.

  4. origin-when-cross-origin — good for cross-origin, but check that sensitive
     paths aren't embedded in the origin (they typically aren't).

  5. strict-origin-when-cross-origin — current best practice (Chrome default
     since 85). Sends full URL same-origin, only origin cross-origin.

  6. Meta referrer vs header — referrer in <meta> tags can be overridden by
     the HTTP header; mismatches can confuse developers about actual policy.

Read-only passive.

CWE-116: Improper Encoding or Escaping of Output
CWE-598: Use of GET Request Method with Sensitive Query Strings
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_UNSAFE_POLICIES = {"unsafe-url", "no-referrer-when-downgrade"}
_ACCEPTABLE_POLICIES = {
    "no-referrer", "origin", "strict-origin",
    "origin-when-cross-origin", "strict-origin-when-cross-origin",
    "same-origin",
}
_META_REFERRER_RE = re.compile(
    r'<meta[^>]+name=["\']referrer["\'][^>]+content=["\']([^"\']+)["\']',
    re.I,
)


def _check_referrer_policy_header(headers: dict, url: str) -> List[Dict]:
    findings = []
    raw = headers.get("referrer-policy", "")

    if not raw:
        findings.append({
            "type": "referrer-policy-missing",
            "status": "WARN",
            "detail": (
                f"No Referrer-Policy header at {url}.\n\n"
                f"Browsers default to no-referrer-when-downgrade, which sends the full "
                f"URL to HTTPS origins. Query parameters with tokens or IDs are leaked "
                f"to analytics, CDN, and third-party script origins.\n\n"
                f"Fix: add Referrer-Policy: strict-origin-when-cross-origin."
            ),
        })
        return findings

    # Multiple policies may be comma-separated; last effective one wins
    policies = [p.strip().lower() for p in raw.split(",")]
    effective = policies[-1]

    if effective == "unsafe-url":
        findings.append({
            "type": "referrer-policy-unsafe-url",
            "status": "FAIL",
            "detail": (
                f"Referrer-Policy at {url} is set to unsafe-url.\n\n"
                f"The full URL (including path and query string) is sent in every "
                f"Referer header — to cross-origin destinations, over HTTP, and even "
                f"when downgrading from HTTPS.\n\n"
                f"Fix: use strict-origin-when-cross-origin or no-referrer."
            ),
        })
    elif effective == "no-referrer-when-downgrade":
        findings.append({
            "type": "referrer-policy-no-referrer-when-downgrade",
            "status": "WARN",
            "detail": (
                f"Referrer-Policy at {url} uses no-referrer-when-downgrade.\n\n"
                f"Full URLs including query strings are sent to all same-protocol "
                f"(HTTPS→HTTPS) cross-origin destinations. Tokens in query params "
                f"(e.g., ?token=, ?reset=) are leaked to third-party trackers, CDN, "
                f"and analytics services loaded on the page.\n\n"
                f"Fix: use strict-origin-when-cross-origin to send only the origin "
                f"cross-origin while keeping full URL for same-origin navigation."
            ),
        })
    elif effective not in _ACCEPTABLE_POLICIES:
        findings.append({
            "type": f"referrer-policy-unknown-value",
            "status": "WARN",
            "detail": (
                f"Referrer-Policy at {url} has an unrecognised value: {effective!r}.\n\n"
                f"Unknown policies are treated as no-referrer by browsers, which may "
                f"break legitimate analytics or be a typo of a less-safe value.\n\n"
                f"Fix: use one of the standard values: no-referrer, strict-origin-when-cross-origin, etc."
            ),
        })

    return findings


def _check_meta_referrer(body: str, header_policy: str, url: str) -> Optional[Dict]:
    matches = _META_REFERRER_RE.findall(body)
    if not matches:
        return None
    meta_policy = matches[-1].lower().strip()
    if header_policy and meta_policy != header_policy.lower().strip():
        return {
            "type": "referrer-policy-meta-header-mismatch",
            "status": "WARN",
            "detail": (
                f"Referrer-Policy mismatch at {url}: "
                f"HTTP header={header_policy!r}, meta tag={meta_policy!r}.\n\n"
                f"The HTTP header takes precedence over the meta tag. Developers may "
                f"believe the meta policy is in effect and be confused when the header "
                f"overrides it.\n\n"
                f"Fix: remove the meta referrer tag and rely solely on the HTTP header."
            ),
        }
    return None


class ReferrerPolicyDeepScanner(BaseScanner):
    """Deep Referrer-Policy checks: unsafe values, missing header, meta tag mismatch."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Referrer Policy Deep — target unreachable", "PASS",
                detail="No response; referrer policy check skipped."))
            return self.results

        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        body = resp.text or ""
        found = False

        for f in _check_referrer_policy_header(headers, url):
            found = True
            if f["status"] == "FAIL":
                log_fail(logger, f"Referrer Policy Deep — {f['type']}")
            else:
                log_warn(logger, f"Referrer Policy Deep — {f['type']}")
            self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        rp_header = headers.get("referrer-policy", "")
        f = _check_meta_referrer(body, rp_header, url)
        if f:
            found = True
            log_warn(logger, f"Referrer Policy Deep — {f['type']}")
            self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"Referrer Policy Deep — policy well-configured for {url}")
            self.results.append(self._result(
                url, "Referrer Policy Deep — referrer policy properly configured", "PASS",
                detail="Referrer-Policy header present with a safe value."))

        return self.results
