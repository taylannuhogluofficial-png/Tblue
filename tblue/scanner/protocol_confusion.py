"""
Protocol Confusion Security Scanner.

HTTP/HTTPS protocol confusion occurs when:
- A site intended to be HTTPS-only also responds on HTTP (mixed deployment)
- HTTP version leaks HTTPS credentials/tokens via Referer or form POST
- Redirect chains downgrade from HTTPS to HTTP before upgrading again
- Insecure site on the same domain can set/override cookies

Security issues:

1. Site accessible on both HTTP and HTTP (no enforced redirect):
   - Attackers on-path can intercept HTTP connections and steal session tokens,
     even if the primary HTTPS site is secure.
2. HTTP redirect to HTTPS doesn't use HSTS:
   - First-visit HTTP → HTTPS redirect is intercepted by MITM.
   - Without HSTS, browser makes HTTP requests on subsequent visits.
3. HTTP → HTTP redirect (not upgrading to HTTPS):
   - Sensitive paths never redirect to HTTPS.
4. Mixed content redirect chain:
   - HTTPS → HTTP → HTTPS (bouncing back causes token leakage in Referer).
5. HTTP site on same superdomain can set cookies for HTTPS subdomain:
   - http://example.com can set cookies for .example.com, poisoning HTTPS subdomains.
6. Upgrade-Insecure-Requests not sent or honored:
   - Server doesn't serve the Upgrade-Insecure-Requests header.

CWE-319: Cleartext Transmission of Sensitive Information
CWE-311: Missing Encryption of Sensitive Data
"""

from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)


class ProtocolConfusionScanner(BaseScanner):
    """Detect HTTP/HTTPS protocol confusion vulnerabilities."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0

        parsed = urlparse(url)
        scheme  = parsed.scheme.lower()
        host    = parsed.netloc
        path    = parsed.path or "/"

        # Build HTTP and HTTPS variants
        http_url  = f"http://{host}{path}"
        https_url = f"https://{host}{path}"

        # Probe HTTP version
        try:
            http_resp = self.http.get(http_url)
        except Exception:
            http_resp = None

        # Probe HTTPS version
        try:
            https_resp = self.http.get(https_url)
        except Exception:
            https_resp = None

        if http_resp is None and https_resp is None:
            self.results.append(self._result(
                url, "Protocol confusion — no response on either HTTP or HTTPS", "PASS",
                detail="Neither HTTP nor HTTPS probe received a response."
            ))
            return self.results

        # Case 1: HTTP accessible with 200 (not redirecting to HTTPS)
        if http_resp and http_resp.status_code == 200:
            if https_resp and https_resp.status_code in (200, 301, 302):
                log_fail(logger, f"Site accessible on HTTP (200) at {http_url}")
                self.results.append(self._result(
                    url,
                    "Protocol confusion — site returns HTTP 200 (not redirecting to HTTPS)",
                    "FAIL",
                    detail=(
                        f"'{http_url}' returns HTTP 200 instead of redirecting to HTTPS. "
                        "An on-path attacker can intercept unencrypted HTTP connections, "
                        "steal session cookies, inject malicious content, or perform "
                        "credential theft even if the HTTPS site is otherwise secure. "
                        "Fix: configure the web server to redirect all HTTP traffic to "
                        "HTTPS with a 301 redirect and add Strict-Transport-Security header."
                    )
                ))
                findings += 1
            elif https_resp is None:
                log_warn(logger, f"Only HTTP accessible (no HTTPS) at {http_url}")
                self.results.append(self._result(
                    url,
                    "Protocol confusion — site accessible on HTTP but not HTTPS",
                    "FAIL",
                    detail=(
                        f"'{http_url}' returns HTTP 200 but HTTPS is not available. "
                        "All data including credentials and session tokens is transmitted "
                        "in cleartext, exposed to MITM interception. "
                        "Fix: deploy TLS and migrate the site to HTTPS-only."
                    )
                ))
                findings += 1

        # Case 2: HTTP redirects to HTTP (not HTTPS)
        if http_resp and http_resp.status_code in (301, 302, 303, 307, 308):
            location = ""
            if hasattr(http_resp.headers, "get"):
                location = http_resp.headers.get("location", http_resp.headers.get("Location", ""))
            elif isinstance(http_resp.headers, dict):
                location = http_resp.headers.get("location", http_resp.headers.get("Location", ""))

            if location and location.startswith("http://"):
                log_warn(logger, f"HTTP redirects to HTTP (not HTTPS) at {url}")
                self.results.append(self._result(
                    url,
                    f"Protocol confusion — HTTP redirect target is also HTTP: {location[:80]}",
                    "WARN",
                    detail=(
                        f"'{http_url}' redirects to '{location[:80]}' (still HTTP). "
                        "The redirect chain never upgrades to HTTPS, leaving the connection "
                        "cleartext throughout. "
                        "Fix: ensure HTTP redirects always point to https:// destinations."
                    )
                ))
                findings += 1
            elif location and location.startswith("https://"):
                # Good — HTTP redirects to HTTPS. Check for HSTS
                if https_resp:
                    hsts = ""
                    if hasattr(https_resp.headers, "get"):
                        hsts = https_resp.headers.get("strict-transport-security",
                               https_resp.headers.get("Strict-Transport-Security", ""))
                    elif isinstance(https_resp.headers, dict):
                        hsts = https_resp.headers.get("strict-transport-security",
                               https_resp.headers.get("Strict-Transport-Security", ""))
                    if not hsts:
                        log_warn(logger, f"HTTP→HTTPS redirect without HSTS at {url}")
                        self.results.append(self._result(
                            url,
                            "Protocol confusion — HTTP redirects to HTTPS but HSTS is absent",
                            "WARN",
                            detail=(
                                "HTTP correctly redirects to HTTPS, but the HTTPS response "
                                "lacks Strict-Transport-Security. Without HSTS, the first "
                                "visit via HTTP can be intercepted (SSL stripping attack). "
                                "Fix: add Strict-Transport-Security: max-age=31536000; "
                                "includeSubDomains; preload to HTTPS responses."
                            )
                        ))
                        findings += 1

        # Case 3: Check for Upgrade-Insecure-Requests in CSP
        if https_resp and https_resp.status_code == 200:
            csp = ""
            if hasattr(https_resp.headers, "get"):
                csp = https_resp.headers.get("content-security-policy",
                      https_resp.headers.get("Content-Security-Policy", ""))
            elif isinstance(https_resp.headers, dict):
                csp = https_resp.headers.get("content-security-policy",
                      https_resp.headers.get("Content-Security-Policy", ""))
            if csp and "upgrade-insecure-requests" not in csp.lower():
                log_warn(logger, f"CSP without upgrade-insecure-requests at {url}")
                self.results.append(self._result(
                    url,
                    "Protocol confusion — CSP present but missing upgrade-insecure-requests",
                    "WARN",
                    detail=(
                        "Content-Security-Policy is present but does not include "
                        "'upgrade-insecure-requests'. This directive instructs browsers to "
                        "silently upgrade HTTP sub-resource requests to HTTPS, preventing "
                        "mixed content and protocol downgrade. "
                        "Fix: add 'upgrade-insecure-requests;' to your CSP."
                    )
                ))
                findings += 1

        if not self.results:
            log_pass(logger, f"No protocol confusion issues at {url}")
            self.results.append(self._result(
                url, "Protocol confusion — HTTP properly redirects to HTTPS", "PASS",
                detail="HTTP redirects to HTTPS (or only HTTPS is accessible). No protocol confusion detected."
            ))

        return self.results
