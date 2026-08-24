"""
JSONP Endpoint Security Scanner.

JSONP (JSON with Padding) is a legacy technique for cross-origin data access
that wraps JSON responses in a JavaScript function call. The callback function
name is supplied by the requester as a URL parameter.

Security issues:

1. JSONP endpoints with arbitrary callback:
   - `GET /api/user?callback=alert` → `alert({"name": "admin", "email": "..."})`
   - Any page can include this as a <script src="...">, bypassing CORS.
   - Attacker steals all data in the response without CORS restrictions.

2. JSONP used for authenticated endpoints:
   - If the endpoint sends cookies (the browser includes them with <script>),
     the attacker's page receives the victim's authenticated data.

3. Callback parameter with XSS payload:
   - `?callback=<script>alert(1)</script>` — if reflected without sanitization.

4. Content-Type not JavaScript:
   - Returning `Content-Type: application/json` for JSONP response — browser
     may still execute it in older browsers.

5. Callback name validation bypass:
   - `?callback=1;alert(1);var x=` — if only prefix is validated.

6. JSONP on mutation-sensitive endpoints:
   - API that accepts GET with callback can leak state-changing responses.

Detection:
- Probe for callback/jsonp/cb URL parameters that reflect in the response body
  wrapped in a function call pattern.
- Check for existing script-src restrictions that would limit JSONP exploitation.

CWE-829: Inclusion of Functionality from Untrusted Control Sphere
CWE-352: Cross-Site Request Forgery (CSRF)
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_CALLBACK_PARAMS = ["callback", "jsonp", "cb", "jsoncallback", "json_callback", "call", "func", "fn"]
_MARKER = "tblue_jsonp_test_marker"

_JSONP_RESPONSE_RE = re.compile(
    r'^(?:[a-zA-Z_$][a-zA-Z0-9_$]*)?\s*\(',
)

_CALLBACK_IN_BODY_RE = re.compile(
    r'^' + re.escape(_MARKER) + r'\s*\(',
)

_SCRIPT_INJECTION_IN_CB = re.compile(
    r'(?:<script|javascript:|<img\b)',
    re.I
)

_JSONP_ENDPOINTS = [
    "/api/user", "/api/profile", "/api/me", "/api/session",
    "/api/data", "/api/info", "/api/config", "/user.json",
    "/account.json", "/profile.json", "/whoami",
]


class JSONPEndpointScanner(BaseScanner):
    """Detect JSONP endpoints that enable cross-origin data theft."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0

        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        # Also probe the URL itself
        probe_urls = [url] + [base + p for p in _JSONP_ENDPOINTS[:6]]

        for probe_url in probe_urls:
            if findings >= 8:
                break

            for param in _CALLBACK_PARAMS[:4]:
                if findings >= 8:
                    break
                test_url = probe_url + ("&" if "?" in probe_url else "?") + f"{param}={_MARKER}"
                try:
                    resp = self.http.get(test_url)
                except Exception:
                    continue
                if resp is None or resp.status_code not in (200,):
                    continue

                body = (resp.text or "").strip()
                if not body:
                    continue

                # Check if our marker appears as a function call prefix
                if _CALLBACK_IN_BODY_RE.match(body):
                    log_fail(logger, f"JSONP endpoint with arbitrary callback at {test_url}")
                    self.results.append(self._result(
                        url,
                        f"JSONP endpoint — arbitrary callback reflected: {probe_url.replace(base, '')}?{param}=",
                        "FAIL",
                        detail=(
                            f"'{probe_url}' reflects the '{param}' parameter as a JSONP "
                            "function call wrapper. Any website can include this endpoint as "
                            "a <script src='...'> and the callback receives the full JSON "
                            "response — bypassing CORS entirely. If this endpoint returns "
                            "authenticated user data, attackers can steal it from logged-in victims. "
                            "Fix: remove JSONP support and use proper CORS headers instead; "
                            "validate callback values against a strict allowlist if JSONP is required."
                        )
                    ))
                    findings += 1
                    break  # Found JSONP for this endpoint, move on

                # Check if body starts with any function-call pattern (pre-existing JSONP)
                elif _JSONP_RESPONSE_RE.match(body) and _MARKER not in body:
                    # Pre-existing JSONP callback
                    log_warn(logger, f"Existing JSONP response pattern at {probe_url}")
                    self.results.append(self._result(
                        url,
                        f"JSONP endpoint — pre-configured JSONP response format detected: {probe_url.replace(base, '')}",
                        "WARN",
                        detail=(
                            f"'{probe_url}' returns a JSONP-style response "
                            f"(starts with a function call). JSONP responses bypass CORS "
                            "and allow any cross-origin page to read the data. "
                            "Fix: replace JSONP with CORS headers; remove callback parameter support."
                        )
                    ))
                    findings += 1
                    break

        if not self.results:
            log_pass(logger, f"No JSONP endpoints detected at {url}")
            self.results.append(self._result(
                url, "JSONP endpoint — no JSONP callback reflection detected", "PASS",
                detail="No JSONP-style endpoints found that reflect arbitrary callback parameters."
            ))

        return self.results
