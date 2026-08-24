"""
HTTP Verb Tampering / Method Override Scanner.

Some frameworks respect X-HTTP-Method-Override, X-Method-Override, or
_method parameters to allow clients to tunnel DELETE/PUT/PATCH through
POST. If these overrides bypass authorization checks that validate the
HTTP method, an attacker can delete or modify resources.

Also checks:
- TRACE method enabled (XST — Cross-Site Tracing, reflects Authorization headers)
- DEBUG method enabled (ASP.NET debug mode; can expose process info)
- Arbitrary method acceptance (servers responding 200 to garbage methods)

CWE-650: Trusting HTTP Permission Methods on the Server Side
CWE-749: Exposed Dangerous Method or Function
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-Method-Override",
    "X-HTTP-Method",
]

_OVERRIDE_PARAMS = ["_method", "method", "_httpMethod", "httpMethod"]

_DANGEROUS_METHODS = ["TRACE", "DEBUG", "TRACK"]

_TRACE_REFLECT_RE = re.compile(r"TRACE\s+/", re.I)

# Methods that should NEVER be accepted on normal web resources
_EXOTIC_METHODS = ["FOOBAR", "TBLUE_PROBE"]


class HTTPVerbTamperingScanner(BaseScanner):
    """Detects HTTP verb tampering, TRACE/DEBUG, and method override bypass."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping HTTP verb tampering checks: {url}")
            self.results.append(self._result(
                url, "HTTP verb tampering — no response", "PASS",
                detail="Target did not respond; verb tampering checks skipped."
            ))
            return self.results

        self._check_trace_method(url)
        self._check_method_override_headers(url)
        self._check_method_override_params(url)
        self._check_arbitrary_method(url)

        if not self.results:
            log_pass(logger, f"No HTTP verb tampering issues: {url}")
            self.results.append(self._result(
                url, "HTTP verb tampering — no issues detected", "PASS",
                detail=(
                    "TRACE/DEBUG disabled, method-override headers and params "
                    "not accepted, arbitrary HTTP methods rejected."
                )
            ))

        return self.results

    def _check_trace_method(self, url: str) -> None:
        # Use OPTIONS to see allowed methods first
        r = self.http.options(url)
        if r is not None:
            allow = r.headers.get("Allow", "").upper()
            if "TRACE" in allow:
                log_fail(logger, f"TRACE method in Allow header: {url}")
                self.results.append(self._result(
                    url,
                    "HTTP verb tampering — TRACE method enabled (Allow header)",
                    "FAIL",
                    detail=(
                        "The server's Allow header includes TRACE. "
                        "TRACE method reflects the full request back to the client including "
                        "Authorization, Cookie, and custom headers — enabling Cross-Site Tracing "
                        "(XST). Fix: disable TRACE in server config "
                        "(Apache: TraceEnable off; Nginx: limit_except GET POST {...}; "
                        "IIS: remove TRACE from allowed verbs)."
                    )
                ))
                return
            if "DEBUG" in allow:
                log_fail(logger, f"DEBUG method in Allow header: {url}")
                self.results.append(self._result(
                    url,
                    "HTTP verb tampering — DEBUG method enabled (ASP.NET)",
                    "FAIL",
                    detail=(
                        "The server's Allow header includes DEBUG. "
                        "ASP.NET DEBUG method can expose process environment information. "
                        "Fix: disable debug mode in production web.config; "
                        "set <compilation debug='false'/>."
                    )
                ))
                return

    def _check_method_override_headers(self, url: str) -> None:
        # POST with method-override header claiming DELETE
        for header in _OVERRIDE_HEADERS:
            r = self.http.post(url, headers={header: "DELETE"})
            if r is None:
                continue
            # A 2xx with an override header for DELETE suggests bypass
            if r.status_code in (200, 202, 204):
                log_warn(logger, f"Method override via {header}: DELETE accepted: {url}")
                self.results.append(self._result(
                    url,
                    f"HTTP verb tampering — {header}: DELETE override accepted (2xx response)",
                    "WARN",
                    detail=(
                        f"POST request with '{header}: DELETE' header returned {r.status_code}. "
                        "If authorization checks validate HTTP method (GET/POST/etc.) but not "
                        "the override header, an attacker can bypass DELETE/PUT restrictions. "
                        "Fix: ignore X-HTTP-Method-Override in production; "
                        "validate authorization based on the effective intended action, "
                        "not just the HTTP verb."
                    )
                ))
                return  # One finding per category

    def _check_method_override_params(self, url: str) -> None:
        # POST with _method=DELETE in body
        for param in _OVERRIDE_PARAMS:
            r = self.http.post(url, data={param: "DELETE"})
            if r is None:
                continue
            if r.status_code in (200, 202, 204):
                log_warn(logger, f"Method override via param '{param}'=DELETE: {url}")
                self.results.append(self._result(
                    url,
                    f"HTTP verb tampering — '{param}'=DELETE parameter override accepted (2xx)",
                    "WARN",
                    detail=(
                        f"POST request with body parameter '{param}=DELETE' returned {r.status_code}. "
                        "Legacy Rails/PHP frameworks that process _method override can be tricked "
                        "into treating POST requests as DELETE/PUT operations. "
                        "Fix: disable _method override in production frameworks; "
                        "or ensure authorization checks the intended operation, not just HTTP verb."
                    )
                ))
                return

    def _check_arbitrary_method(self, url: str) -> None:
        # Servers should return 405 for unrecognized methods
        for method in _EXOTIC_METHODS:
            try:
                parsed = urlparse(url)
                session = self.http._session if hasattr(self.http, "_session") else None
                if session is None:
                    return
                r = session.request(method, url, timeout=10)
                if r is not None and r.status_code in (200, 201):
                    log_warn(logger, f"Arbitrary method {method!r} accepted: {url}")
                    self.results.append(self._result(
                        url,
                        f"HTTP verb tampering — arbitrary method '{method}' accepted (2xx)",
                        "WARN",
                        detail=(
                            f"The server returned {r.status_code} for HTTP method '{method}', "
                            "which is not a valid HTTP method. "
                            "Correctly configured servers should return 405 Method Not Allowed. "
                            "This may indicate the server passes all methods to the application "
                            "layer without filtering, which can enable verb tampering."
                        )
                    ))
                    return
            except Exception:
                continue
