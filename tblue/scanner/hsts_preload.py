"""
HSTS Preload Security Scanner.

HTTP Strict Transport Security (HSTS) forces browsers to use HTTPS only.
However, the basic HSTS header (`Strict-Transport-Security: max-age=...`)
has a bootstrap problem: on first visit over HTTP, the header is not yet
received, leaving the user vulnerable to a "first-visit" SSL strip attack.

The **HSTS preload list** (maintained by Google, recognized by all major
browsers) solves this: domains on the list are hardcoded to require HTTPS
even on first visit, before any HTTP request is ever made.

Prerequisites for preload inclusion (hstspreload.org requirements):
1. Valid HTTPS certificate
2. All HTTP traffic redirects to HTTPS
3. All subdomains served over HTTPS
4. HSTS header on HTTPS response with:
   - max-age >= 31536000 (1 year)
   - includeSubDomains directive
   - preload directive

This scanner goes beyond basic HSTS checking (covered in headers.py) to:
1. Check for the `preload` directive in the HSTS header
2. Check that `includeSubDomains` is present (required for preload)
3. Verify max-age >= 31536000 (1 year, as required by hstspreload.org)
4. Detect HTTPS→HTTP redirect (anti-pattern)
5. Detect HTTP access points that don't redirect to HTTPS
6. Flag HSTS on HTTP (ignored by browsers, misconfiguration)

References:
  hstspreload.org
  RFC 6797: HTTP Strict Transport Security (HSTS)
  MDN: Strict-Transport-Security
  Scott Helme: "HSTS Preloading"
  OWASP: A02:2021 Cryptographic Failures
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Minimum max-age required for preload (1 year in seconds)
_PRELOAD_MIN_MAX_AGE = 31536000

# Regex to extract max-age value
_MAX_AGE_RE = re.compile(r"max-age\s*=\s*(\d+)", re.I)


class HSTSPreloadScanner(BaseScanner):
    """Check HSTS header completeness and preload eligibility."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed = urlparse(url)

        # 1. Check HTTPS HSTS header
        https_url = url if parsed.scheme == "https" else url.replace("http://", "https://", 1)
        http_url = url if parsed.scheme == "http" else url.replace("https://", "http://", 1)

        self._check_https_hsts(https_url)
        self._check_http_redirect(http_url, https_url)

        return self.results

    def _check_https_hsts(self, https_url: str) -> None:
        """Analyse the HSTS header on the HTTPS response."""
        resp = self.http.get(https_url)
        if resp is None:
            self.results.append(self._result(
                https_url,
                "HSTS preload — HTTPS endpoint unreachable",
                "WARN",
                detail="Could not fetch the HTTPS version of the URL to check HSTS.",
            ))
            return

        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        hsts_value = headers.get("strict-transport-security", "").strip()

        if not hsts_value:
            log_warn(logger, f"HSTS preload: no HSTS header on {https_url}")
            self.results.append(self._result(
                https_url,
                "HSTS preload — Strict-Transport-Security header missing",
                "WARN",
                detail=(
                    "No Strict-Transport-Security (HSTS) header found on the HTTPS response. "
                    "Without HSTS, browsers will happily visit the HTTP version of this site, "
                    "leaving users vulnerable to SSL strip attacks on first visit. "
                    "Fix: add Strict-Transport-Security: max-age=31536000; "
                    "includeSubDomains; preload"
                ),
            ))
            return

        # Parse max-age
        max_age = self._parse_max_age(hsts_value)
        has_include_subdomains = "includesubdomains" in hsts_value.lower()
        has_preload = "preload" in hsts_value.lower()

        # Check max-age
        if max_age is None:
            log_warn(logger, f"HSTS preload: missing max-age on {https_url}")
            self.results.append(self._result(
                https_url,
                "HSTS preload — max-age missing from HSTS header",
                "WARN",
                detail=(
                    f"The HSTS header ('{hsts_value}') is missing the max-age directive. "
                    "Browsers ignore HSTS headers without max-age. "
                    "Fix: add max-age=31536000 (1 year) to the HSTS header."
                ),
            ))
            return

        if max_age == 0:
            log_warn(logger, f"HSTS preload: max-age=0 (HSTS removal) on {https_url}")
            self.results.append(self._result(
                https_url,
                "HSTS preload — max-age=0 (HSTS being removed)",
                "WARN",
                detail=(
                    "The HSTS header has max-age=0, which instructs browsers to delete "
                    "any cached HSTS policy for this domain. After this, browsers will "
                    "no longer force HTTPS for this domain. "
                    "Fix: set max-age=31536000 to maintain HSTS enforcement."
                ),
            ))
            return

        if max_age < _PRELOAD_MIN_MAX_AGE:
            log_warn(logger, f"HSTS preload: max-age {max_age} < 31536000 on {https_url}")
            self.results.append(self._result(
                https_url,
                f"HSTS preload — max-age too short ({max_age}s < 31536000s required)",
                "WARN",
                detail=(
                    f"The HSTS max-age is {max_age} seconds, which is less than the "
                    f"minimum required for preload eligibility ({_PRELOAD_MIN_MAX_AGE}s = 1 year). "
                    "A shorter max-age means users are unprotected after the cache expires, "
                    "and the domain cannot be submitted to the HSTS preload list. "
                    "Fix: set max-age=31536000 or higher."
                ),
            ))

        # Check includeSubDomains
        if not has_include_subdomains:
            log_warn(logger, f"HSTS preload: includeSubDomains missing on {https_url}")
            self.results.append(self._result(
                https_url,
                "HSTS preload — includeSubDomains directive missing",
                "WARN",
                detail=(
                    "The HSTS header is missing the 'includeSubDomains' directive. "
                    "Without it:\n"
                    "• Subdomains can still be accessed over HTTP, allowing SSL strip attacks\n"
                    "• The domain is not eligible for the HSTS preload list\n"
                    "• Cookie injection via subdomains remains possible\n"
                    "Fix: add includeSubDomains to the HSTS header — but first ensure ALL "
                    "subdomains are properly served over HTTPS."
                ),
            ))

        # Check preload directive
        if not has_preload:
            log_warn(logger, f"HSTS preload: preload directive missing on {https_url}")
            self.results.append(self._result(
                https_url,
                "HSTS preload — preload directive missing (not preload-eligible)",
                "WARN",
                detail=(
                    "The HSTS header is missing the 'preload' directive. "
                    "Without 'preload', the domain cannot be submitted to the HSTS preload list "
                    "(hstspreload.org), so users are only protected from the second visit onward "
                    "(after receiving the HSTS header). First-visit users remain vulnerable to "
                    "SSL strip attacks.\n"
                    "Fix: add 'preload' to the HSTS header and submit at hstspreload.org. "
                    "Ensure includeSubDomains is also set and max-age >= 31536000. "
                    "WARNING: preload is difficult to undo — all subdomains must be HTTPS first."
                ),
            ))

        # If all checks pass
        if max_age >= _PRELOAD_MIN_MAX_AGE and has_include_subdomains and has_preload:
            log_pass(logger, f"HSTS preload: fully preload-eligible on {https_url}")
            self.results.append(self._result(
                https_url,
                "HSTS preload — fully preload-eligible HSTS header",
                "PASS",
                detail=(
                    f"HSTS header is correctly configured with max-age={max_age}, "
                    "includeSubDomains, and preload directives. The domain is eligible for "
                    "submission to the HSTS preload list (hstspreload.org). "
                    "If not already submitted, consider doing so for maximum protection."
                ),
            ))

    def _check_http_redirect(self, http_url: str, https_url: str) -> None:
        """Check that HTTP redirects to HTTPS."""
        resp = self.http.get(http_url)
        if resp is None:
            return

        status = resp.status_code or 0
        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        location = headers.get("location", "")

        if status in (301, 302, 307, 308):
            if location.startswith("https://"):
                log_pass(logger, f"HSTS preload: HTTP → HTTPS redirect present at {http_url}")
                self.results.append(self._result(
                    http_url,
                    "HSTS preload — HTTP redirects to HTTPS",
                    "PASS",
                    detail=(
                        f"HTTP requests are correctly redirected to HTTPS "
                        f"(HTTP {status} → {location}). "
                        "This ensures users are upgraded to HTTPS even if they type http://."
                    ),
                ))
            else:
                log_warn(logger, f"HSTS preload: HTTP redirect to non-HTTPS at {http_url}")
                self.results.append(self._result(
                    http_url,
                    "HSTS preload — HTTP redirects to non-HTTPS location",
                    "WARN",
                    detail=(
                        f"HTTP requests are redirected (HTTP {status}) but the Location header "
                        f"('{location}') does not start with 'https://'. "
                        "Users may end up on an HTTP page. "
                        "Fix: ensure all HTTP → HTTPS redirects point to the HTTPS version."
                    ),
                ))
        elif status == 200:
            hsts_on_http = headers.get("strict-transport-security", "")
            if hsts_on_http:
                log_warn(logger, f"HSTS preload: HSTS header on HTTP response at {http_url}")
                self.results.append(self._result(
                    http_url,
                    "HSTS preload — HSTS header sent over HTTP (browsers ignore it)",
                    "WARN",
                    detail=(
                        "The HTTP (non-HTTPS) response includes a Strict-Transport-Security header. "
                        "Browsers ONLY process HSTS headers received over HTTPS — sending HSTS "
                        "over HTTP is ignored and indicates a misconfiguration. "
                        "Fix: redirect HTTP to HTTPS before serving HSTS headers."
                    ),
                ))
            else:
                log_warn(logger, f"HSTS preload: HTTP accessible without redirect at {http_url}")
                self.results.append(self._result(
                    http_url,
                    "HSTS preload — HTTP version accessible (no redirect to HTTPS)",
                    "WARN",
                    detail=(
                        "The HTTP version of this URL returns 200 OK without redirecting to HTTPS. "
                        "This means users accessing http:// get plain HTTP responses, which are "
                        "vulnerable to SSL strip, man-in-the-middle, and content injection attacks. "
                        "Fix: redirect all HTTP traffic to HTTPS with a 301 Permanent redirect."
                    ),
                ))

    def _parse_max_age(self, hsts_value: str) -> Optional[int]:
        """Extract max-age integer from HSTS header value."""
        m = _MAX_AGE_RE.search(hsts_value)
        if m:
            return int(m.group(1))
        return None
