"""
HTTP method enumeration scanner for Tblue.

Sends OPTIONS to each scanned URL and checks which HTTP methods are allowed.
Dangerous methods (TRACE, CONNECT) → FAIL.
Unexpected write methods (PUT, DELETE on non-API paths) → WARN.
"""

import re
from typing import List, Dict, Any, Set
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Methods that should never be enabled on a production web server
_DANGEROUS_METHODS: Set[str] = {"TRACE", "TRACK", "CONNECT", "DEBUG"}

# Methods that are unusual on non-API paths
_WRITE_METHODS: Set[str] = {"PUT", "DELETE", "PATCH"}

# Path patterns that suggest a REST API (write methods are expected there)
_API_PATH_RE = re.compile(r"/api[/v]|/rest/|/v\d+/|/graphql", re.I)

# Some servers return 200 for every OPTIONS (even when they don't support it)
# — validate by also checking if the Allow header is present
_ALLOW_HEADER_NAMES = ("allow", "public", "access-control-allow-methods")


def _parse_allow(resp) -> Set[str]:
    """Extract the set of allowed HTTP methods from the OPTIONS response."""
    for name in _ALLOW_HEADER_NAMES:
        value = resp.headers.get(name, "")
        if value:
            return {m.strip().upper() for m in value.split(",") if m.strip()}
    return set()


class HTTPMethodsScanner(BaseScanner):
    """
    Checks which HTTP methods are enabled on scanned pages.

    Detects:
    - TRACE / TRACK / DEBUG enabled (cross-site tracing attacks)
    - PUT / DELETE on non-API paths (accidental write access)
    - Missing Allow header (server doesn't respond to OPTIONS)
    """

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        resp = self.http.options(url)

        if not resp:
            return self.results

        if resp.status_code not in (200, 204, 405):
            return self.results

        allowed = _parse_allow(resp)

        if not allowed:
            log_pass(logger, f"OPTIONS returns no Allow header — {url}")
            self.results.append(self._result(
                url, "HTTP methods — Allow header not present", "PASS",
                detail="Server does not advertise allowed methods via OPTIONS / Allow header."
            ))
            return self.results

        is_api = bool(_API_PATH_RE.search(urlparse(url).path))
        problems: List[str] = []

        # ── Dangerous methods ──────────────────────────────────────────────
        dangerous_found = allowed & _DANGEROUS_METHODS
        if dangerous_found:
            methods_str = ", ".join(sorted(dangerous_found))
            log_fail(logger, f"Dangerous HTTP method(s) enabled on {url}: {methods_str}")
            problems.append(methods_str)
            self.results.append(self._result(
                url, f"HTTP methods — dangerous method(s) enabled: {methods_str}", "FAIL",
                detail=(
                    f"The server allows {methods_str} on {url}. "
                    + ("TRACE/TRACK enable Cross-Site Tracing (XST) attacks that can bypass "
                       "HttpOnly cookie protection. " if {"TRACE", "TRACK"} & dangerous_found else "")
                    + ("DEBUG can expose internal diagnostics. " if "DEBUG" in dangerous_found else "")
                    + "Fix: disable these methods in your web server config. "
                    "Apache: TraceEnable Off. Nginx: add 'if ($request_method ~ ^(TRACE|TRACK)$) { return 405; }'"
                )
            ))

        # ── Write methods on non-API paths ─────────────────────────────────
        write_found = allowed & _WRITE_METHODS
        if write_found and not is_api:
            methods_str = ", ".join(sorted(write_found))
            log_warn(logger, f"Write HTTP method(s) on non-API path {url}: {methods_str}")
            self.results.append(self._result(
                url, f"HTTP methods — write method(s) on non-API path: {methods_str}", "WARN",
                detail=(
                    f"The server allows {methods_str} on {url} which does not appear to be an API path. "
                    "Unexpected write methods may allow file upload (PUT) or deletion (DELETE). "
                    "Fix: restrict write methods to API paths only using web server config or a WAF rule."
                )
            ))

        if not problems and not (write_found and not is_api):
            log_pass(logger, f"HTTP methods OK on {url}: {', '.join(sorted(allowed))}")
            self.results.append(self._result(
                url, "HTTP methods", "PASS",
                detail=f"Allowed methods: {', '.join(sorted(allowed))}. No dangerous methods detected."
            ))

        return self.results
