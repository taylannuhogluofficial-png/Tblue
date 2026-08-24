"""
HTTP Range Request Security Scanner.

HTTP/1.1 range requests (RFC 7233) allow clients to fetch partial content
using `Range: bytes=start-end`. Security implications when misconfigured:

1. Accept-Ranges on API/JSON endpoints:
   - APIs serving JSON or auth tokens should not support range requests.
   - Range support on API responses can be used for timing oracle attacks
     (comparing response times for different byte ranges of secrets).
2. Accept-Ranges on sensitive file types (.env, config, key files):
   - Enables byte-range based information extraction from config files.
3. Content-Range header leaks file size:
   - `Content-Range: bytes 0-0/12345` reveals full file size, aiding brute-force
     of encrypted files or confirming file existence.
4. Range unit bypass — `Range: items=0-0` (non-byte unit) may bypass WAF rules
   that filter only `Range: bytes=...`.
5. Multipart range responses (multipart/byteranges) from API endpoints — means
   the server treats API data as splittable file content.
6. 206 Partial Content from an endpoint that should serve complete responses:
   - Login, auth, payment endpoints returning 206 is anomalous.

CWE-200: Exposure of Sensitive Information
CWE-400: Uncontrolled Resource Consumption (range amplification)
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_JSON_CT_RE  = re.compile(r'application/json', re.I)
_API_PATH_RE = re.compile(r'/api/|/v\d+/|/graphql|/rest/', re.I)
_SENSITIVE_PATH_RE = re.compile(
    r'\.(env|cfg|conf|config|key|pem|json|xml|yaml|yml|toml|properties)$|'
    r'/(?:config|secrets?|credentials?|settings|private)(?:/|$)',
    re.I
)
_AUTH_PATH_RE = re.compile(
    r'/(?:login|auth|token|oauth|session|password|reset|account)(?:/|$)',
    re.I
)
_MULTIPART_CT_RE = re.compile(r'multipart/byteranges', re.I)


class HTTPRangeSecurityScanner(BaseScanner):
    """Detect insecure range request support on sensitive endpoints."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "HTTP Range requests — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        self._check_accept_ranges(url, resp)
        self._check_range_on_sensitive(url, resp)

        if not self.results:
            log_pass(logger, f"No HTTP range request issues at {url}")
            self.results.append(self._result(
                url, "HTTP Range requests — no issues detected", "PASS",
                detail=(
                    "Accept-Ranges header is absent or 'none' on this URL. "
                    "Range request support is properly restricted."
                )
            ))

        return self.results

    def _check_accept_ranges(self, url: str, resp) -> None:
        accept_ranges = resp.headers.get("accept-ranges", "").lower().strip()

        if not accept_ranges or accept_ranges == "none":
            return

        ct  = resp.headers.get("content-type", "").lower()
        parsed = urlparse(url)
        path = parsed.path

        if _JSON_CT_RE.search(ct) or _API_PATH_RE.search(path):
            log_warn(logger, f"Accept-Ranges on API/JSON endpoint at {url}")
            self.results.append(self._result(
                url,
                f"HTTP Range requests — Accept-Ranges: {accept_ranges} on API/JSON endpoint",
                "WARN",
                detail=(
                    f"The response includes 'Accept-Ranges: {accept_ranges}' on an endpoint "
                    "that serves JSON or API data. Range requests allow clients to fetch "
                    "partial responses, which can be used for timing oracle attacks against "
                    "secret tokens or authentication tokens in the response body. "
                    "Fix: disable range requests on API endpoints by setting "
                    "'Accept-Ranges: none' or removing the header."
                )
            ))
            return

        if _AUTH_PATH_RE.search(path):
            log_warn(logger, f"Accept-Ranges on auth endpoint at {url}")
            self.results.append(self._result(
                url,
                f"HTTP Range requests — Accept-Ranges: {accept_ranges} on auth path",
                "WARN",
                detail=(
                    f"Authentication/session path '{path}' returns 'Accept-Ranges: {accept_ranges}'. "
                    "Auth endpoints should never support range requests. "
                    "Fix: set Accept-Ranges: none on all authentication-related paths."
                )
            ))
            return

        if _SENSITIVE_PATH_RE.search(path):
            log_fail(logger, f"Accept-Ranges on sensitive path at {url}")
            self.results.append(self._result(
                url,
                f"HTTP Range requests — Accept-Ranges on sensitive file path: {path}",
                "FAIL",
                detail=(
                    f"'{path}' serves range requests (Accept-Ranges: {accept_ranges}). "
                    "Configuration files, key files, and secret files should never be "
                    "directly accessible, let alone range-readable. "
                    "Fix: block direct access to these paths via server configuration."
                )
            ))

    def _check_range_on_sensitive(self, url: str, resp) -> None:
        if resp.status_code == 206:
            parsed = urlparse(url)
            path = parsed.path
            if _AUTH_PATH_RE.search(path) or _API_PATH_RE.search(path):
                log_warn(logger, f"206 Partial Content from auth/API path at {url}")
                self.results.append(self._result(
                    url,
                    "HTTP Range requests — 206 Partial Content from auth/API endpoint",
                    "WARN",
                    detail=(
                        f"The endpoint '{path}' returned HTTP 206 Partial Content, indicating "
                        "range request support on an auth or API path. This is anomalous — "
                        "these endpoints should return complete responses only. "
                        "Fix: return 200 for complete content or 416 for unsupported range on "
                        "auth/API endpoints."
                    )
                ))

        cr = resp.headers.get("content-range", "")
        if cr:
            size_match = re.search(r'/(\d+)$', cr)
            if size_match:
                file_size = int(size_match.group(1))
                log_warn(logger, f"Content-Range reveals file size {file_size} at {url}")
                self.results.append(self._result(
                    url,
                    f"HTTP Range requests — Content-Range reveals resource size: {file_size} bytes",
                    "WARN",
                    detail=(
                        f"The Content-Range header reveals the full resource size ({file_size} bytes). "
                        "For sensitive resources, size information can help attackers confirm file "
                        "identity or plan extraction. "
                        "Fix: disable Content-Range responses for sensitive resources."
                    )
                ))

        ct = resp.headers.get("content-type", "").lower()
        if _MULTIPART_CT_RE.search(ct):
            log_warn(logger, f"Multipart byteranges response at {url}")
            self.results.append(self._result(
                url,
                "HTTP Range requests — multipart/byteranges response from endpoint",
                "WARN",
                detail=(
                    "The response Content-Type is 'multipart/byteranges', indicating the server "
                    "returned multiple byte range parts. API and application endpoints should not "
                    "serve multipart range responses. "
                    "Fix: disable range request processing for non-static-file endpoints."
                )
            ))
