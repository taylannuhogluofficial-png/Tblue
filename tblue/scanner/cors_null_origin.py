"""
CORS Null Origin Security Scanner.

Sends a cross-origin request with `Origin: null` and checks whether the server
responds with `Access-Control-Allow-Origin: null`. This is a well-known CORS
misconfiguration.

The `null` origin can be triggered by:
  - Sandboxed iframes: `<iframe sandbox="allow-scripts" src="attacker.com">`
    — pages inside sandboxed iframes get origin: null
  - Local file pages: file:// URLs have origin null
  - Data URIs: `<iframe src="data:text/html,...">` — data: URIs have null origin
  - Redirected cross-origin requests (in some browser versions)
  - Server-Side Rendered pages served via `about:blank`

If the server allows null origin and also allows credentials:
  An attacker-controlled sandboxed iframe can make credentialed requests to
  the target API, reading protected responses — effectively a CORS bypass.

Reference: PortSwigger Web Academy "CORS vulnerabilities"
CWE-942: Permissive Cross-domain Policy with Untrusted Domains
CVSS: 7.5 (High) when combined with credentials
"""

from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_NULL_ORIGIN = "null"


class CORSNullOriginScanner(BaseScanner):
    """Detect CORS misconfiguration allowing null origin."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        try:
            resp = self.http.get(url, headers={"Origin": _NULL_ORIGIN})
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "CORS null origin — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "").lower()

        if acao.strip() == "null":
            if acac == "true":
                log_fail(logger, f"CORS allows null origin with credentials at {url}")
                self.results.append(self._result(
                    url,
                    "CORS null origin — Access-Control-Allow-Origin: null with Allow-Credentials: true",
                    "FAIL",
                    detail=(
                        "The server responds to Origin: null with both "
                        "'Access-Control-Allow-Origin: null' and 'Access-Control-Allow-Credentials: true'. "
                        "An attacker can embed a sandboxed iframe (sandbox='allow-scripts allow-forms') "
                        "pointing to a page that makes credentialed requests to this endpoint. "
                        "The null origin is trusted, so the response (including auth-restricted data) "
                        "is readable by the sandboxed page. "
                        "Fix: never allow null origin in Access-Control-Allow-Origin; "
                        "use an explicit allowlist of trusted origins."
                    )
                ))
            else:
                log_warn(logger, f"CORS allows null origin (no credentials) at {url}")
                self.results.append(self._result(
                    url,
                    "CORS null origin — Access-Control-Allow-Origin: null (without credentials)",
                    "WARN",
                    detail=(
                        "The server responds to Origin: null with 'Access-Control-Allow-Origin: null'. "
                        "Even without credentials, sandboxed iframes or data-URI pages can read "
                        "unauthenticated responses from this endpoint. "
                        "Fix: remove 'null' from the CORS origin allowlist; use explicit trusted origins."
                    )
                ))
        else:
            log_pass(logger, f"CORS correctly rejects null origin at {url}")
            self.results.append(self._result(
                url, "CORS null origin — server does not allow null origin", "PASS",
                detail=(
                    f"Origin: null was sent; server responded with ACAO='{acao or '(absent)'}'. "
                    "The null origin is not allowed."
                )
            ))

        return self.results
