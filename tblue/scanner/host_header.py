"""
Host header injection detection.

Sends requests with common host-override headers used by reverse proxies
(X-Forwarded-Host, X-Host, X-Forwarded-Server, X-HTTP-Host-Override, Forwarded)
and checks whether the injected value is reflected in the response.

Reflection in Location, Link, or body means the app trusts client-supplied
host headers — enabling cache poisoning and password-reset link hijacking.
All checks are read-only (no state change).
"""

import re
from typing import List, Dict, Any

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_PROBE_VALUE = "tblue-hostprobe.invalid"

_OVERRIDE_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "X-Original-Host",
]

_BODY_RE = re.compile(re.escape(_PROBE_VALUE), re.I)


class HostHeaderScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        reflected = []

        for header in _OVERRIDE_HEADERS:
            try:
                resp = self.http.get(url, headers={header: _PROBE_VALUE})
            except Exception:
                continue
            if resp is None:
                continue

            # Check Location / Link response headers
            for resp_header in ("Location", "Link", "Refresh", "Content-Location"):
                val = resp.headers.get(resp_header, "")
                if _PROBE_VALUE.lower() in val.lower():
                    reflected.append((header, f"reflected in {resp_header} response header"))
                    log_fail(logger, f"Host header injection: {header} reflected in {resp_header}")

            # Check response body
            if _BODY_RE.search(resp.text or ""):
                reflected.append((header, "reflected in response body"))
                log_fail(logger, f"Host header injection: {header} reflected in response body")

        if reflected:
            for inj_header, location in reflected:
                self.results.append(self._result(url,
                    f"Host header injection — {inj_header} {location}",
                    "FAIL",
                    detail=(
                        f"Sending {inj_header}: {_PROBE_VALUE} caused the value to be "
                        f"{location}. This means the application blindly trusts "
                        f"client-supplied host override headers. "
                        f"Consequences: HTTP cache poisoning (serving attacker-controlled "
                        f"URLs to all users), password-reset link hijacking "
                        f"(reset emails contain attacker's domain). "
                        f"Fix: validate the Host header against a whitelist of allowed "
                        f"domains in your framework/reverse proxy config. "
                        f"In Nginx: use 'server_name' directives and reject unmatched "
                        f"values. In Apache: use a default VHost that returns 421."
                    )))
        else:
            log_pass(logger, "No host header injection detected")
            self.results.append(self._result(url,
                "Host header injection — not detected",
                "PASS",
                detail=(
                    f"Requests with {', '.join(_OVERRIDE_HEADERS)} set to a probe value "
                    f"did not cause the value to be reflected in response headers or body. "
                    f"The application does not appear to trust client-supplied host headers."
                )))

        return self.results
