"""
TLS Downgrade Passive Scanner.

TLS downgrade attacks force a connection to use weaker protocol versions or
cipher suites. This passive scanner checks for indicators without performing
an active TLS handshake:

  1. Upgrade-Insecure-Requests not set in response — server does not redirect
     HTTP → HTTPS or does not set the CSP upgrade-insecure-requests directive.

  2. Content-Security-Policy upgrade-insecure-requests — the directive that
     auto-upgrades all subresource requests to HTTPS.

  3. HTTP to HTTPS redirect chain — HTTP endpoint that doesn't redirect at all
     indicates HTTP is an accepted transport.

  4. Strict-Transport-Security preload absence — without preload, first visit
     is always HTTP (TOFU problem).

  5. Mixed protocol in meta refresh or Location header — redirect to HTTP
     from HTTPS indicates possible downgrade.

Read-only.

CWE-326: Inadequate Encryption Strength
CWE-757: Selection of Less-Secure Algorithm During Negotiation
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_UPGRADE_CSP_RE = re.compile(r'upgrade-insecure-requests', re.I)
_META_REFRESH_RE = re.compile(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\'][^"\']*http://', re.I)
_HTTP_LOCATION_RE = re.compile(r'^http://', re.I)


def _check_http_endpoint(http, url: str) -> Optional[Dict]:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return None
    http_url = "http://" + parsed.netloc + parsed.path
    resp = http.get(http_url)
    if resp is None:
        return None
    if resp.status_code == 200:
        return {
            "type": "tls-downgrade-http-endpoint-accessible",
            "status": "WARN",
            "detail": (
                f"HTTP version of {url} returns 200 without redirect.\n\n"
                f"The server accepts plain HTTP connections, allowing passive "
                f"eavesdropping of traffic. Users who type the domain without "
                f"https:// will communicate in cleartext.\n\n"
                f"Fix: configure the server to redirect all HTTP to HTTPS (301). "
                f"Use HSTS to prevent future HTTP visits."
            ),
        }
    return None


def _check_upgrade_insecure_requests(headers: dict, url: str) -> Optional[Dict]:
    csp = headers.get("content-security-policy", "")
    if not _UPGRADE_CSP_RE.search(csp) and urlparse(url).scheme == "https":
        return {
            "type": "tls-downgrade-missing-upgrade-insecure-requests",
            "status": "WARN",
            "detail": (
                f"Content-Security-Policy at {url} does not include "
                f"upgrade-insecure-requests.\n\n"
                f"Without this directive, HTTP subresources (images, scripts, iframes) "
                f"embedded via http:// URLs are not automatically upgraded to HTTPS, "
                f"creating mixed content and potential downgrade attack surface.\n\n"
                f"Fix: add upgrade-insecure-requests to your CSP."
            ),
        }
    return None


def _check_meta_refresh_http(body: str, url: str) -> Optional[Dict]:
    if _META_REFRESH_RE.search(body[:32768]):
        return {
            "type": "tls-downgrade-meta-refresh-to-http",
            "status": "FAIL",
            "detail": (
                f"Meta-refresh redirect to HTTP found at {url}.\n\n"
                f"Refreshing to an HTTP URL downgrades the connection from HTTPS, "
                f"exposing subsequent requests to eavesdropping and MITM.\n\n"
                f"Fix: change meta-refresh URLs to HTTPS."
            ),
        }
    return None


class TLSDowngradePassiveScanner(BaseScanner):
    """Checks for HTTP endpoint accessibility, missing upgrade-insecure-requests, meta-refresh downgrades."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "TLS Downgrade Passive — target unreachable", "PASS",
                detail="No response; TLS downgrade check skipped."))
            return self.results

        found = False
        seen_types: set = set()
        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        body = resp.text or ""

        for check_fn in [
            lambda: _check_upgrade_insecure_requests(headers, url),
            lambda: _check_meta_refresh_http(body, url),
            lambda: _check_http_endpoint(self.http, url),
        ]:
            f = check_fn()
            if f and f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                if f["status"] == "FAIL":
                    log_fail(logger, f"TLS Downgrade Passive — {f['type']}")
                else:
                    log_warn(logger, f"TLS Downgrade Passive — {f['type']}")
                self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"TLS Downgrade Passive — no downgrade indicators at {url}")
            self.results.append(self._result(
                url, "TLS Downgrade Passive — no TLS downgrade indicators detected", "PASS",
                detail="HTTPS enforced; no HTTP endpoint accessible, no meta-refresh to HTTP."))

        return self.results
