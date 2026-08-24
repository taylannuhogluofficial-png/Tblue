"""
HTTP Response Splitting / CRLF Injection Deep Scanner.

CRLF injection (CR=\\r, LF=\\n) in HTTP headers enables:
  - Response splitting: inject a second complete HTTP response
  - Header injection: add arbitrary headers (Set-Cookie, Location, etc.)
  - Cache poisoning: inject headers that affect downstream caches
  - XSS via injected headers (some browsers interpret injected Content-Type)

This scanner probes reflection vectors more comprehensively than the basic
crlf_injection.py scanner:

  1. Multiple header contexts — probes standard redirect/redirect parameters
     but also Location, Set-Cookie reflection in API endpoints.
  2. Encoding variants — tests raw CRLF, URL-encoded (%0d%0a), double-encoded
     (%250d%250a), and Unicode CR/LF (%E5%98%8A%E5%98%8D).
  3. Probe header detection — injects a custom header value and checks if it
     appears in the response headers.
  4. Cookie injection — probes for CRLF that lands in a Set-Cookie response.

Read-only. Probes are benign strings that won't persist server-side.

CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail

logger = get_logger(__name__)

_PROBE_HDR_NAME  = "X-TBL9Z7X-Probe"
_PROBE_HDR_VALUE = "crlftest"

_CRLF_VARIANTS = [
    ("%0d%0a",      "url-encoded"),
    ("%0D%0A",      "url-encoded-upper"),
    ("%250d%250a",  "double-encoded"),
    ("%E5%98%8A%E5%98%8D",  "unicode-crlf"),
    ("\r\n",        "raw"),
    ("%0a",         "lf-only"),
]

_REDIRECT_PARAMS = [
    "next", "redirect", "url", "return", "returnTo", "goto", "location",
    "redirect_uri", "target", "destination",
]

_HEADERS_TO_CHECK = [
    "location",
    "set-cookie",
    "x-tbl9z7x-probe",
    "content-type",
    "x-injection-probe",
]


def _inject_payload(base_url: str, param: str, crlf: str) -> str:
    """Build a test URL injecting CRLF into a query parameter."""
    sep   = "&" if "?" in base_url else "?"
    value = f"https://example.com{crlf}{_PROBE_HDR_NAME}: {_PROBE_HDR_VALUE}"
    return f"{base_url}{sep}{param}={value}"


def _check_injection_in_headers(resp) -> bool:
    """True if our probe header or a blank header injection appears in response."""
    if resp is None:
        return False
    for h in _HEADERS_TO_CHECK:
        val = resp.headers.get(h, "")
        if _PROBE_HDR_VALUE in val:
            return True
    # Check for double Set-Cookie (sign of header injection)
    if hasattr(resp.headers, "getlist"):
        cookies = resp.headers.getlist("set-cookie")
        if len(cookies) > 1:
            for c in cookies:
                if _PROBE_HDR_VALUE in c:
                    return True
    return False


def _probe_crlf(http, base_url: str, param: str) -> Optional[Dict]:
    for crlf, variant in _CRLF_VARIANTS:
        test_url = _inject_payload(base_url, param, crlf)
        resp = http.get(test_url)
        if resp is None:
            continue
        if resp.status_code in (400, 403, 414, 422, 431):
            continue
        if _check_injection_in_headers(resp):
            return {
                "param":   param,
                "variant": variant,
                "url":     test_url[:200],
            }
    return None


_PROBE_PATHS = [
    "",
    "/login",
    "/redirect",
    "/api/v1/redirect",
    "/oauth/authorize",
    "/search",
]


class HTTPResponseSplittingScanner(BaseScanner):
    """Deep CRLF / HTTP response splitting probe with encoding bypass variants."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "HTTP Response Splitting — target unreachable", "PASS",
                detail="No response; CRLF injection check skipped."))
            return self.results

        parsed      = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        found       = False

        for path in _PROBE_PATHS:
            ep_base = base_origin + path
            for param in _REDIRECT_PARAMS[:5]:  # limit to 5 params per path
                hit = _probe_crlf(self.http, ep_base, param)
                if hit:
                    found = True
                    log_fail(logger, f"HTTP Response Splitting — CRLF via {hit['variant']} in {param} at {ep_base}")
                    self.results.append(self._result(
                        ep_base,
                        f"HTTP Response Splitting — CRLF via {hit['variant']} in param '{param}'",
                        "FAIL",
                        detail=(
                            f"CRLF injection detected at {ep_base}?{param}=... using "
                            f"'{hit['variant']}' encoding.\n\n"
                            f"HTTP response splitting allows attackers to inject arbitrary "
                            f"headers into the response, enabling: Set-Cookie injection "
                            f"(session fixation), Location header hijacking (open redirect), "
                            f"cache poisoning, and XSS via Content-Type injection.\n\n"
                            f"Fix: sanitize all user-controlled input that is reflected in "
                            f"HTTP response headers. Strip or reject CR (\\r) and LF (\\n) "
                            f"characters before writing them into headers."
                        ),
                    ))
                    break  # one finding per endpoint is enough

        if not found:
            log_pass(logger, f"HTTP Response Splitting — no CRLF injection found for {url}")
            self.results.append(self._result(
                url,
                "HTTP Response Splitting — no CRLF injection detected",
                "PASS",
                detail=(
                    f"Probed {len(_PROBE_PATHS)} paths × {min(5, len(_REDIRECT_PARAMS))} "
                    f"params × {len(_CRLF_VARIANTS)} CRLF encoding variants. "
                    f"No header injection detected."
                ),
            ))

        return self.results
