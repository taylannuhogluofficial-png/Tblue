"""
Private Network Access (PNA) Security Scanner.

Private Network Access (formerly CORS-RFC1918) is a W3C specification that
prevents public websites from making requests to private network resources
(localhost, 192.168.x, 10.x, 172.16-31.x) via the user's browser.

Chrome 98+ enforces PNA preflight checks: a CORS preflight with
`Access-Control-Request-Private-Network: true` must receive
`Access-Control-Allow-Private-Network: true` in the response.

Security issues:

1. API responses on private IP addresses accepting cross-origin requests:
   - Attacker page can make authenticated requests to internal APIs via victim's browser.
   - E.g., router admin panels, IoT devices, internal services.
2. localhost endpoints with permissive CORS:
   - Developer tools, database admin UIs, internal metrics running on localhost.
3. Missing ACAO-Private-Network on valid private network endpoints:
   - Causes browsers to block legitimate cross-origin requests (hardening signal).
4. Private network endpoints returning ACAO: * (wildcard):
   - All public pages can read data from internal APIs.
5. Site served from private IP with public CORS headers (ACAO: *):
   - Internal service inadvertently exposed to the public internet AND accepting cross-origin.

CWE-918: Server-Side Request Forgery (SSRF) — related boundary
CWE-441: Unintended Proxy/Intermediary
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_RFC1918_RE = re.compile(
    r'^(?:https?://)?(?:'
    r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3}'
    r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|127\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    r'|localhost'
    r'|::1'
    r')(?::\d+)?(?:/|$)',
    re.I
)

_PRIVATE_API_PATHS = [
    "/api/", "/api/v1/", "/api/v2/", "/api/internal/",
    "/admin/api/", "/internal/", "/_internal/",
    "/graphql", "/metrics", "/health", "/status",
]

_ACAO_HEADER = "access-control-allow-origin"
_ACAPN_HEADER = "access-control-allow-private-network"


def _get_header(resp, key: str) -> str:
    if hasattr(resp.headers, "get"):
        return resp.headers.get(key, resp.headers.get(key.title(), ""))
    if isinstance(resp.headers, dict):
        return resp.headers.get(key, resp.headers.get(key.title(), ""))
    return ""


class PrivateNetworkAccessScanner(BaseScanner):
    """Detect Private Network Access (PNA) security issues."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0

        parsed = urlparse(url)
        host = parsed.netloc.split(":")[0].lower()
        is_private_network = bool(_RFC1918_RE.match(f"{parsed.scheme}://{parsed.netloc}/"))

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "Private network access — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        acao = _get_header(resp, _ACAO_HEADER).strip()
        acapn = _get_header(resp, _ACAPN_HEADER).strip()

        # Case 1: Private network host with ACAO: *
        if is_private_network and acao == "*":
            log_fail(logger, f"Private network host with ACAO: * at {url}")
            self.results.append(self._result(
                url,
                "Private network access — private IP host returns Access-Control-Allow-Origin: *",
                "FAIL",
                detail=(
                    f"The target at '{url}' is on a private network address and returns "
                    "Access-Control-Allow-Origin: *. Any public web page can read responses "
                    "from this endpoint via the user's browser, enabling cross-origin data "
                    "exfiltration from internal network resources. "
                    "Fix: restrict CORS on private network resources to only trusted public origins; "
                    "implement PNA preflight handling (Access-Control-Allow-Private-Network: true)."
                )
            ))
            findings += 1

        # Case 2: Private network host with ACAO pointing to external origin
        elif is_private_network and acao and acao != "null":
            if not acao.startswith("https://" + host) and not acao.startswith("http://" + host):
                log_warn(logger, f"Private network host with external ACAO at {url}")
                self.results.append(self._result(
                    url,
                    f"Private network access — private host allows cross-origin access: {acao[:60]}",
                    "WARN",
                    detail=(
                        f"Private network host '{url}' returns CORS headers allowing access from "
                        f"'{acao}'. Cross-origin requests to private network resources via a "
                        "user's browser can expose internal APIs and services. "
                        "Fix: review whether this private endpoint needs cross-origin access; "
                        "restrict ACAO to the minimum required public origin."
                    )
                ))
                findings += 1

        # Probe API paths on the target for private network exposure
        base = f"{parsed.scheme}://{parsed.netloc}"
        for api_path in _PRIVATE_API_PATHS[:5]:
            if findings >= 8:
                break
            probe_url = base + api_path
            try:
                probe = self.http.get(probe_url)
            except Exception:
                continue
            if probe is None or probe.status_code not in (200, 401, 403):
                continue

            probe_acao = _get_header(probe, _ACAO_HEADER).strip()
            if probe_acao == "*" and probe.status_code == 200:
                log_warn(logger, f"API endpoint with ACAO: * on {probe_url}")
                self.results.append(self._result(
                    url,
                    f"Private network access — API path with ACAO: * (public data): {api_path}",
                    "WARN",
                    detail=(
                        f"The API endpoint '{api_path}' returns HTTP 200 with "
                        "Access-Control-Allow-Origin: *. Any website can read this API's "
                        "responses. If this data is user-specific or sensitive, this is a "
                        "data exposure. Fix: restrict ACAO to specific trusted origins."
                    )
                ))
                findings += 1

        if not self.results:
            if is_private_network:
                log_warn(logger, f"Private network host — CORS not configured at {url}")
                self.results.append(self._result(
                    url,
                    "Private network access — private network host without public CORS (expected for internal services)",
                    "PASS",
                    detail="Private network host with no ACAO headers — correctly not exposing cross-origin access."
                ))
            else:
                log_pass(logger, f"No private network access issues at {url}")
                self.results.append(self._result(
                    url, "Private network access — no PNA security issues detected", "PASS",
                    detail="No private network exposure or overly permissive CORS on API endpoints detected."
                ))

        return self.results
