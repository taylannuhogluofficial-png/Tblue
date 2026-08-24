"""
Referrer-Policy Header Security Scanner.

The HTTP Referrer-Policy header controls how much referrer information is
included in requests and navigation events. Without a proper policy, sensitive
information in URLs (tokens, session IDs, user IDs, private paths) leaks to:

1. **Third-party analytics / ad networks** — any <img>, <script>, <link> tag
   causes the browser to send the current URL as the Referer header.

2. **External link destinations** — clicking an <a href="https://external.com">
   while on https://app.example.com/reset?token=abc sends the token to external.com.

3. **Server logs of external parties** — permanently recorded.

4. **Downgrade attacks** — if page is HTTPS but loads HTTP subresources,
   the full URL leaks to the HTTP server (downgraded in transit).

Real-world impact:
- Password reset links containing tokens leaked to analytics (HackerOne reports)
- Session tokens in URL parameters exposed to CDN logs
- OAuth redirect URIs with state parameters leaked to third parties

Blue-team checks (passive, header analysis):
1. Presence of Referrer-Policy header
2. Value safety classification (strict-origin, no-referrer are best; unsafe-url is worst)
3. Meta tag referrer overrides in HTML
4. Dangerous patterns: unsafe-url, no-referrer-when-downgrade (default behavior, sends full URL)
5. Inconsistency: HTTPS page with <meta name="referrer" content="unsafe-url">

Policy safety ranking (best → worst):
  no-referrer                → no referrer sent ever (safest)
  same-origin                → only same-origin requests get referrer
  strict-origin              → only origin (no path) sent, HTTPS→HTTP blocked
  strict-origin-when-cross-origin → full URL for same-origin, origin only cross-origin (recommended)
  origin-when-cross-origin   → full URL same-origin, origin cross-origin (acceptable)
  origin                     → only origin sent (no path)
  no-referrer-when-downgrade → full URL unless HTTPS→HTTP (browser default, bad)
  unsafe-url                 → always sends full URL including path+query (worst)

References:
  MDN: Referrer-Policy
  Scott Helme: "A new security header: Referrer Policy"
  https://www.w3.org/TR/referrer-policy/
  OWASP: Sensitive Data Exposure (A02:2021)
  CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Policy value safety levels
_POLICY_SAFE = frozenset({
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
})

_POLICY_ACCEPTABLE = frozenset({
    "origin",
    "origin-when-cross-origin",
})

_POLICY_UNSAFE = frozenset({
    "no-referrer-when-downgrade",  # browser default — full URL unless HTTPS→HTTP
    "unsafe-url",                   # worst: always full URL
})

_KNOWN_POLICIES = _POLICY_SAFE | _POLICY_ACCEPTABLE | _POLICY_UNSAFE

# Regex for <meta name="referrer" content="...">
_META_REFERRER_RE = re.compile(
    r'<meta[^>]+name=["\']referrer["\'][^>]+content=["\']([^"\']+)["\']',
    re.I,
)
_META_REFERRER_RE2 = re.compile(
    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']referrer["\']',
    re.I,
)


class ReferrerPolicyScanner(BaseScanner):
    """Detect Referrer-Policy security issues."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Referrer-Policy — target unreachable", "PASS",
                detail="No response from target.",
            ))
            return self.results

        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        body = resp.text or ""

        header_policy = headers.get("referrer-policy", "").strip().lower()
        meta_policy = self._extract_meta_policy(body)

        self._check_header_presence(url, header_policy, meta_policy)
        self._check_policy_safety(url, header_policy, "header")
        if meta_policy:
            self._check_policy_safety(url, meta_policy, "meta tag")
        self._check_policy_inconsistency(url, header_policy, meta_policy)

        return self.results

    def _extract_meta_policy(self, body: str) -> Optional[str]:
        """Extract Referrer-Policy from <meta name="referrer"> tag."""
        try:
            soup = BeautifulSoup(body, "html.parser")
            for meta in soup.find_all("meta"):
                name = (meta.get("name") or "").lower()
                if name == "referrer":
                    return (meta.get("content") or "").strip().lower()
        except Exception:
            pass

        for pattern in (_META_REFERRER_RE, _META_REFERRER_RE2):
            m = pattern.search(body)
            if m:
                return m.group(1).strip().lower()
        return None

    def _check_header_presence(self, url: str, header_policy: str, meta_policy: Optional[str]) -> None:
        """Check whether Referrer-Policy header is present."""
        if not header_policy and not meta_policy:
            log_warn(logger, f"Referrer-Policy: header missing on {url}")
            self.results.append(self._result(
                url,
                "Referrer-Policy — header missing",
                "WARN",
                detail=(
                    "The Referrer-Policy HTTP response header is not set and no "
                    "<meta name='referrer'> tag was found. Without this header, browsers use "
                    "the default policy ('no-referrer-when-downgrade'), which sends the full URL "
                    "(including path and query string) to all cross-origin destinations. "
                    "This leaks sensitive URL parameters (tokens, session IDs, user IDs) "
                    "to third-party analytics, ad networks, and external link targets.\n"
                    "Fix: add Referrer-Policy: strict-origin-when-cross-origin to all responses. "
                    "This is the recommended value per the W3C spec and MDN."
                ),
            ))
        elif header_policy:
            log_pass(logger, f"Referrer-Policy header present: '{header_policy}' on {url}")

    def _check_policy_safety(self, url: str, policy: str, source: str) -> None:
        """Classify the policy value and flag if unsafe."""
        if not policy:
            return

        # Normalize: some policies can be comma-separated (multiple values)
        # Browser uses the last recognized value
        parts = [p.strip() for p in policy.split(",")]
        effective = None
        for part in reversed(parts):
            if part in _KNOWN_POLICIES:
                effective = part
                break

        if effective is None:
            if policy:
                log_warn(logger, f"Referrer-Policy: unrecognized value '{policy}' in {source}")
                self.results.append(self._result(
                    url,
                    f"Referrer-Policy — unrecognized policy value in {source}",
                    "WARN",
                    detail=(
                        f"The Referrer-Policy {source} has an unrecognized value: '{policy}'. "
                        "Browsers that don't recognize a value fall back to the browser default "
                        "('no-referrer-when-downgrade'), which leaks full URLs cross-origin. "
                        "Fix: use a recognized value such as 'strict-origin-when-cross-origin'."
                    ),
                ))
            return

        if effective == "unsafe-url":
            log_fail(logger, f"Referrer-Policy: unsafe-url in {source} on {url}")
            self.results.append(self._result(
                url,
                f"Referrer-Policy — unsafe-url policy set in {source}",
                "FAIL",
                detail=(
                    f"The Referrer-Policy {source} is set to 'unsafe-url', the least secure "
                    "option. This causes the browser to always include the full URL (scheme, "
                    "host, path, and query string) in Referer headers for ALL requests, "
                    "including cross-origin, HTTPS→HTTP. "
                    "Tokens, session IDs, and private paths are exposed to every third-party "
                    "resource (analytics, CDNs, ads) and external link destination.\n"
                    "Fix: change to 'no-referrer' or 'strict-origin-when-cross-origin'."
                ),
            ))
        elif effective == "no-referrer-when-downgrade":
            log_warn(logger, f"Referrer-Policy: no-referrer-when-downgrade in {source} on {url}")
            self.results.append(self._result(
                url,
                f"Referrer-Policy — weak policy 'no-referrer-when-downgrade' in {source}",
                "WARN",
                detail=(
                    f"The Referrer-Policy {source} uses 'no-referrer-when-downgrade', "
                    "which is equivalent to the browser default (no Referrer-Policy at all). "
                    "This sends the full URL to all cross-origin HTTPS destinations and blocks "
                    "referrer only on HTTPS→HTTP downgrades. "
                    "Sensitive URL parameters (tokens, IDs) are still exposed to third parties.\n"
                    "Fix: upgrade to 'strict-origin-when-cross-origin' or stricter."
                ),
            ))
        elif effective in _POLICY_SAFE:
            log_pass(logger, f"Referrer-Policy: safe value '{effective}' in {source} on {url}")
            self.results.append(self._result(
                url,
                f"Referrer-Policy — safe policy '{effective}' in {source}",
                "PASS",
                detail=(
                    f"The Referrer-Policy {source} is set to '{effective}', "
                    "which is a safe value. Referrer information is appropriately restricted."
                ),
            ))
        elif effective in _POLICY_ACCEPTABLE:
            log_pass(logger, f"Referrer-Policy: acceptable value '{effective}' in {source} on {url}")
            self.results.append(self._result(
                url,
                f"Referrer-Policy — acceptable policy '{effective}' in {source}",
                "PASS",
                detail=(
                    f"The Referrer-Policy {source} is set to '{effective}'. "
                    "This is acceptable but consider upgrading to 'strict-origin-when-cross-origin' "
                    "for stronger protection against path/query leakage in cross-origin requests."
                ),
            ))

    def _check_policy_inconsistency(
        self, url: str, header_policy: str, meta_policy: Optional[str]
    ) -> None:
        """Detect when header and meta tag disagree on policy safety."""
        if not header_policy or not meta_policy:
            return

        header_unsafe = any(p.strip() in _POLICY_UNSAFE for p in header_policy.split(","))
        meta_unsafe = any(p.strip() in _POLICY_UNSAFE for p in meta_policy.split(","))

        if header_unsafe != meta_unsafe:
            log_warn(logger, f"Referrer-Policy: header and meta tag disagree on {url}")
            self.results.append(self._result(
                url,
                "Referrer-Policy — header and meta tag have inconsistent policies",
                "WARN",
                detail=(
                    f"The Referrer-Policy HTTP header ('{header_policy}') and "
                    f"<meta name='referrer'> tag ('{meta_policy}') specify different policies. "
                    "The meta tag overrides the HTTP header for navigation from the page, "
                    "which can lead to unexpected referrer leakage. "
                    "Fix: ensure both the header and meta tag use the same safe policy, "
                    "or remove the meta tag and rely solely on the HTTP header."
                ),
            ))
