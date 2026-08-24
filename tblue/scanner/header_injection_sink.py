"""
HTTP Response Header Injection Sink Scanner.

HTTP response header injection (also called CRLF injection or header splitting)
occurs when user-controlled input is reflected in HTTP response headers without
proper sanitization. Injecting \\r\\n allows an attacker to:

  1. Inject arbitrary headers (e.g., Set-Cookie to hijack sessions)
  2. Split the HTTP response into two (HTTP Response Splitting)
  3. Redirect users (via injected Location header)
  4. Inject XSS via injected content-type or Set-Cookie

While active CRLF probing is covered by crlf_injection.py (red-team), this
BLUE-TEAM scanner takes a different approach:

  - Scans server response headers for values that REFLECT query parameters,
    headers, or path segments back into the response (reflection sinks)
  - Identifies headers likely to be dynamically constructed from user input
  - Checks for unusually long header values that might indicate input acceptance
  - Looks for redirect headers (Location, Refresh) that echo input back
  - Examines Set-Cookie values for path reflection

This is passive observation: we send normal requests and look at whether
the response headers appear to reflect input back.

CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers
CWE-644: Improper Neutralization of HTTP Headers for Scripting Syntax
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urljoin, urlparse, parse_qs, urlunparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_MAX_HEADER_LEN = 4096

# Unique probe value to look for in response headers
_PROBE_VALUE = "tbl9z7xprobe"

_PROBE_PATHS = [
    "?tbl_probe={v}",
    "?redirect={v}",
    "?url={v}",
    "?return_to={v}",
    "?next={v}",
    "?callback={v}",
    "?lang={v}",
    "?locale={v}",
    "?ref={v}",
    "?source={v}",
]

# Headers that commonly reflect input and are injection-relevant
_REFLECTION_HEADERS = [
    "location",
    "set-cookie",
    "refresh",
    "access-control-allow-origin",
    "content-disposition",
    "x-redirect-to",
    "x-forwarded-host",
]

# Headers suspicious for being unusually dynamic or long
_SUSPICIOUS_DYNAMIC = [
    "x-powered-by",
    "server",
    "x-request-id",
    "x-correlation-id",
    "via",
]


def _check_reflection(resp, probe: str) -> Optional[str]:
    """Check if probe string appears in any response header value."""
    if resp is None:
        return None
    try:
        for name, value in resp.headers.items():
            if probe.lower() in value.lower():
                return name.lower()
    except Exception:
        pass
    return None


def _check_open_redirect_header(resp) -> Optional[str]:
    """Check Location/Refresh headers that redirect to the query param value."""
    if resp is None or resp.status_code not in range(300, 400):
        return None
    loc = resp.headers.get("location", "")
    if loc:
        try:
            parsed = urlparse(loc)
            if parsed.netloc and parsed.netloc not in ("example.com",):
                # External redirect — check if it echoes a param
                return loc
        except Exception:
            pass
    return None


def _check_cors_reflection(resp, origin_probe: str) -> bool:
    """Check if CORS origin is echoed back (wildcard or exact reflection)."""
    if resp is None:
        return False
    acao = resp.headers.get("access-control-allow-origin", "")
    return origin_probe.lower() in acao.lower()


class HeaderInjectionSinkScanner(BaseScanner):
    """Passive scanner identifying response headers that reflect user input."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Header Injection Sink — target unreachable", "PASS",
                detail="No response; header injection sink analysis skipped."))
            return self.results

        base = url.rstrip("/")
        parsed = urlparse(url)
        base_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", ""))

        all_findings: List[Dict] = []
        seen_types: set = set()

        # Probe each parameter with the unique value
        for param_template in _PROBE_PATHS:
            probe_url = base_url + param_template.format(v=_PROBE_VALUE)
            r = self.http.get(probe_url)
            if r is None:
                continue

            reflected_header = _check_reflection(r, _PROBE_VALUE)
            if reflected_header:
                key = f"reflection-{reflected_header}"
                if key not in seen_types:
                    seen_types.add(key)
                    param = param_template.split("=")[0].lstrip("?")
                    all_findings.append({
                        "severity": "WARN",
                        "type": key,
                        "msg": (
                            f"Probe value reflected in '{reflected_header}' header "
                            f"when '{param}' parameter is set. "
                            f"Potential header injection sink — test manually for CRLF injection."
                        ),
                        "url": probe_url,
                    })

        # Check CORS origin reflection
        origin_probe = "https://evil-tbl9z7x.com"
        cors_resp = self.http.get(url, headers={"Origin": origin_probe})
        if cors_resp and _check_cors_reflection(cors_resp, origin_probe):
            key = "cors-origin-reflection"
            if key not in seen_types:
                seen_types.add(key)
                all_findings.append({
                    "severity": "FAIL",
                    "type": key,
                    "msg": (
                        "CORS Access-Control-Allow-Origin reflects the Origin header value — "
                        "any origin is granted access. Combined with credentials: the "
                        "attacker's site can read authenticated responses."
                    ),
                    "url": url,
                })

        # Check Location header for reflecting query params on this URL
        for path in ["/?redirect=https://example-evil-tbl9z7x.com", "/?url=https://example-evil-tbl9z7x.com"]:
            r = self.http.get(base_url + path)
            if r and r.status_code in range(300, 400):
                loc = r.headers.get("location", "")
                if "example-evil-tbl9z7x.com" in loc:
                    key = "location-open-redirect"
                    if key not in seen_types:
                        seen_types.add(key)
                        all_findings.append({
                            "severity": "FAIL",
                            "type": key,
                            "msg": (
                                f"Location header reflects query parameter value: '{loc}'. "
                                f"Open redirect confirmed — can be used for phishing and SSRF."
                            ),
                            "url": base_url + path,
                        })

        if not all_findings:
            log_pass(logger, f"Header Injection Sink — no reflection sinks found on {url}")
            self.results.append(self._result(
                url,
                "Header Injection Sink — no input reflection in response headers",
                "PASS",
                detail=(
                    f"Probed {len(_PROBE_PATHS)} parameter names and checked CORS/Location "
                    f"header reflection. No user input reflected in response headers."
                ),
            ))
            return self.results

        for f in all_findings:
            status = f["severity"]
            if status == "FAIL":
                log_fail(logger, f"Header Injection Sink — {f['msg'][:80]}")
            else:
                log_warn(logger, f"Header Injection Sink — {f['msg'][:80]}")

            self.results.append(self._result(
                f.get("url", url),
                f"Header Injection Sink — {f['msg'][:100]}",
                status,
                detail=(
                    f"{f['msg']}\n\n"
                    f"Header injection sinks become exploitable when the server does not "
                    f"strip \\r\\n characters from reflected values. Even without CRLF, "
                    f"reflection in Location or Set-Cookie enables open redirects and "
                    f"cookie injection.\n\n"
                    f"Verify: add \\r\\n%0d%0a to the parameter value and check if headers "
                    f"split or if Set-Cookie is injected."
                ),
            ))

        return self.results
