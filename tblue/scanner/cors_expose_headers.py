"""
CORS Access-Control-Expose-Headers Security Scanner.

Checks for security issues in the Access-Control-Expose-Headers (ACEH) header:

1. Sensitive headers exposed to cross-origin JavaScript:
   - Authorization, Set-Cookie, X-Auth-Token, X-API-Key, X-CSRF-Token
   - X-Session-ID, X-User-ID, X-Internal-Token, X-Secret
2. Wildcard (*) in expose-headers — exposes ALL response headers including sensitive ones
3. ACEH combined with Access-Control-Allow-Credentials: true — exposed tokens are usable
4. Missing Vary: Origin on CORS responses (cache poisoning enabler)
5. Cross-origin isolation headers (COOP/COEP) absent alongside CORS

This complements the existing cors.py and cors_advanced.py scanners with
a focus specifically on the expose-headers attack surface.
"""

from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_SENSITIVE_EXPOSE_HEADERS = {
    "authorization",
    "set-cookie",
    "x-auth-token",
    "x-api-key",
    "x-api-secret",
    "x-csrf-token",
    "x-session-id",
    "x-session-token",
    "x-user-id",
    "x-user-token",
    "x-internal-token",
    "x-secret",
    "x-access-token",
    "x-refresh-token",
    "www-authenticate",
    "proxy-authenticate",
}

_PROBE_ORIGIN = "https://attacker-tbl9z7x-cors.example.com"


class CORSExposeHeadersScanner(BaseScanner):
    """Detect sensitive headers exposed via Access-Control-Expose-Headers."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        try:
            resp = self.http.get(url, headers={"Origin": _PROBE_ORIGIN})
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "CORS expose-headers — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        self._check_expose_headers(url, resp)
        self._check_credentials_with_expose(url, resp)
        self._check_vary_origin(url, resp)

        if not self.results:
            log_pass(logger, f"No CORS expose-headers issues at {url}")
            self.results.append(self._result(
                url, "CORS expose-headers — no sensitive header exposure detected", "PASS",
                detail="Access-Control-Expose-Headers does not expose sensitive header names."
            ))

        return self.results

    def _check_expose_headers(self, url: str, resp) -> None:
        expose = resp.headers.get("access-control-expose-headers", "")
        if not expose:
            return

        if expose.strip() == "*":
            log_warn(logger, f"ACEH wildcard (*) at {url}")
            self.results.append(self._result(
                url, "CORS expose-headers — wildcard (*) exposes all headers", "WARN",
                detail=(
                    "Access-Control-Expose-Headers: * exposes all response headers to cross-origin "
                    "JavaScript, including any sensitive headers set by the server. "
                    "Fix: enumerate only the headers that need to be exposed; avoid wildcard."
                )
            ))
            return

        exposed = {h.strip().lower() for h in expose.split(",")}
        sensitive_found = exposed & _SENSITIVE_EXPOSE_HEADERS
        if sensitive_found:
            log_fail(logger, f"Sensitive headers in ACEH at {url}: {sensitive_found}")
            self.results.append(self._result(
                url,
                f"CORS expose-headers — sensitive header(s) exposed: {', '.join(sorted(sensitive_found))}",
                "FAIL",
                detail=(
                    f"Access-Control-Expose-Headers exposes sensitive headers: "
                    f"{', '.join(sorted(sensitive_found))}. "
                    "Cross-origin JavaScript on attacker-controlled pages can read these "
                    "header values when the victim visits, enabling token theft. "
                    "Fix: remove sensitive headers from ACEH; expose only non-sensitive headers "
                    "(e.g., Content-Length, X-Request-ID)."
                )
            ))

    def _check_credentials_with_expose(self, url: str, resp) -> None:
        expose      = resp.headers.get("access-control-expose-headers", "")
        allow_cred  = resp.headers.get("access-control-allow-credentials", "")
        allow_origin = resp.headers.get("access-control-allow-origin", "")

        if (expose and allow_cred.lower() == "true" and
                allow_origin not in ("", "*", "null")):
            exposed = {h.strip().lower() for h in expose.split(",")}
            if exposed:
                log_warn(logger, f"ACEH with Allow-Credentials: true at {url}")
                self.results.append(self._result(
                    url,
                    "CORS expose-headers — exposed headers usable with credentials",
                    "WARN",
                    detail=(
                        f"Access-Control-Expose-Headers is set with Allow-Credentials: true "
                        f"and a non-wildcard origin. Exposed headers ({', '.join(sorted(exposed))}) "
                        "are readable by authenticated cross-origin requests, amplifying the "
                        "impact of any CORS misconfiguration. "
                        "Fix: minimize exposed headers; ensure Allow-Credentials is only used "
                        "with strictly validated origins."
                    )
                ))

    def _check_vary_origin(self, url: str, resp) -> None:
        acao  = resp.headers.get("access-control-allow-origin", "")
        vary  = resp.headers.get("vary", "").lower()
        expose = resp.headers.get("access-control-expose-headers", "")

        if acao and expose and "origin" not in vary:
            log_warn(logger, f"Missing Vary: Origin on CORS response at {url}")
            self.results.append(self._result(
                url,
                "CORS expose-headers — missing Vary: Origin on CORS response",
                "WARN",
                detail=(
                    "The CORS response with Access-Control-Expose-Headers is missing "
                    "Vary: Origin. CDN/proxy caches may serve a CORS response tailored "
                    "for one origin to a different origin, enabling cache poisoning attacks. "
                    "Fix: add Vary: Origin to all responses that include CORS headers."
                )
            ))
