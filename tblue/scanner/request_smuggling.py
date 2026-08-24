"""
HTTP Request Smuggling Indicator Scanner.

Detects server-side conditions that increase the likelihood of HTTP/1.1 request
smuggling (CL.TE / TE.CL variants).  All checks are read-only and blue-team safe:
no partial requests or desync payloads are sent.

Checks performed:
  1. Response has both Content-Length and Transfer-Encoding headers simultaneously
     — ambiguous per RFC 7230 §3.3.3; compliant servers should reject or normalise
  2. Transfer-Encoding header with obfuscated values (chunked;ext, TE: identity,chunked)
  3. Via/X-Forwarded-* headers indicating a multi-hop proxy chain (classic smuggling setup)
  4. Server + proxy fingerprinting against known-vulnerable version ranges
  5. Ambiguous TE header probe: sends a GET with 'Transfer-Encoding: chunked, identity'
     and records whether the server accepts (200) or rejects (400/501) it

None of these send malformed request bodies or desync payloads; they are purely
header-level observations.  For actual smuggling testing, use Burp Suite Pro's
HTTP Request Smuggler extension in an authorised pentest context.

Paid equivalents: Burp Suite Pro HTTP Request Smuggler, PortSwigger smuggling labs.
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Known-vulnerable server version patterns (regex against Server header)
_VULNERABLE_SERVER_RE = re.compile(
    r"""
    nginx/(?:0\.\d+|1\.(?:[0-9]|1[0-6])\.\d+)                   # nginx < 1.17.x
    | Apache/2\.(?:[01]\.\d+|4\.(?:[01]\d|2[0-4]))\b             # Apache < 2.4.25
    | Microsoft-IIS/(?:[1-9]|10\.0)                               # IIS 10.0 and below
    | LiteSpeed/?                                                  # LiteSpeed (historically)
    | gunicorn/(?:0\.\d+|1[0-9]\.\d+)                             # gunicorn < 20
    """,
    re.I | re.VERBOSE,
)

# Proxy headers that indicate a hop-by-hop proxy chain
_PROXY_HEADER_INDICATORS = [
    "via",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "forwarded",
    "cf-ray",           # Cloudflare
    "x-amz-cf-id",      # AWS CloudFront
    "x-cache",          # Varnish / CDN
    "x-cache-hit",
    "x-edge-location",
    "x-akamai-edgescape",
]

# Transfer-Encoding values other than 'chunked' or 'identity' are suspect
_TE_SUSPICIOUS_RE = re.compile(
    r"(?:xchunked|chunked\s*;|identity\s*,|gzip|deflate|compress)",
    re.I,
)

# Chunked TE regex for detecting dual CL+TE
_TE_CHUNKED_RE = re.compile(r"\bchunked\b", re.I)


class RequestSmugglingScanner(BaseScanner):
    """Detect HTTP request smuggling risk indicators from server responses."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if not resp:
            return self.results

        hdrs = resp.headers

        # 1. Dual CL + TE in response headers (server should not send both)
        cl  = hdrs.get("content-length", "")
        te  = hdrs.get("transfer-encoding", "")
        if cl and te and _TE_CHUNKED_RE.search(te):
            log_warn(logger, f"Dual CL+TE in response headers: CL={cl} TE={te}")
            self.results.append(self._result(
                url, "Request smuggling — dual CL+TE in response headers", "WARN",
                detail=(
                    "The server response contains both Content-Length and "
                    "Transfer-Encoding: chunked headers simultaneously. "
                    "RFC 7230 §3.3.3 requires that a server send only one; receiving both "
                    "suggests the backend does not strictly follow the spec, which is a "
                    "prerequisite for CL.TE and TE.CL request smuggling. "
                    "Fix: configure the web server to strip duplicate transfer headers; "
                    "use HTTP/2 where possible (not susceptible to HTTP/1.1 smuggling)."
                )
            ))

        # 2. Suspicious Transfer-Encoding values in response
        if te and _TE_SUSPICIOUS_RE.search(te):
            log_warn(logger, f"Suspicious Transfer-Encoding value: {te}")
            self.results.append(self._result(
                url, "Request smuggling — suspicious Transfer-Encoding value", "WARN",
                detail=(
                    f"Response Transfer-Encoding header contains an unusual value: '{te}'. "
                    "Non-standard TE values (xchunked, identity,chunked, gzip) can trigger "
                    "inconsistent parsing between frontend proxies and backend servers — a "
                    "requirement for request smuggling. "
                    "Fix: ensure all middleware normalises Transfer-Encoding to 'chunked' or "
                    "removes it entirely for non-chunked responses."
                )
            ))

        # 3. Proxy chain indicators
        proxy_headers_found = [
            h for h in _PROXY_HEADER_INDICATORS if hdrs.get(h)
        ]
        if len(proxy_headers_found) >= 2:
            found_str = ", ".join(proxy_headers_found[:5])
            log_warn(logger, f"Multi-hop proxy chain detected: {found_str}")
            self.results.append(self._result(
                url, "Request smuggling — multi-hop proxy chain detected", "WARN",
                detail=(
                    f"Response includes proxy headers: {found_str}. "
                    "Request smuggling requires a frontend proxy and a backend server that "
                    "disagree on body length parsing. A visible proxy chain confirms the "
                    "multi-hop architecture needed for this class of attack. "
                    "Fix: ensure all hops in the chain use the same HTTP parsing library; "
                    "consider upgrading to HTTP/2 end-to-end; disable HTTP/1.1 keep-alive "
                    "if the proxy chain cannot be unified."
                )
            ))

        # 4. Known-vulnerable server software
        server_hdr = hdrs.get("server", "") or hdrs.get("x-powered-by", "")
        if server_hdr and _VULNERABLE_SERVER_RE.search(server_hdr):
            log_fail(logger, f"Known-vulnerable server version: {server_hdr}")
            self.results.append(self._result(
                url, "Request smuggling — potentially vulnerable server version", "FAIL",
                detail=(
                    f"Server header '{server_hdr}' matches a version range known to have "
                    "HTTP request smuggling vulnerabilities. "
                    "Fix: upgrade to the latest patched version. For nginx: 1.17.x+; "
                    "For Apache: 2.4.25+; For IIS: ensure KB2975629 / latest CU is applied."
                )
            ))

        # 5. Ambiguous TE probe — send a GET with a dual TE header
        self._probe_te_handling(url)

        if not self.results:
            log_pass(logger, f"No request smuggling indicators detected on {url}")
            self.results.append(self._result(
                url, "Request smuggling — no indicators detected", "PASS",
                detail=(
                    "No HTTP request smuggling risk indicators were found in server response "
                    "headers (no dual CL+TE, no suspicious TE values, no known-vulnerable "
                    "server version)."
                )
            ))

        return self.results

    def _probe_te_handling(self, url: str) -> None:
        """
        Send a GET request with an ambiguous Transfer-Encoding header and record
        how the server responds.  'Transfer-Encoding: chunked, identity' is invalid
        per RFC 7230 — a well-configured server should reject it (400) or ignore it.
        Acceptance (200) suggests the server processes non-standard TE values,
        which is a CL.TE/TE.CL risk factor.
        """
        try:
            resp = self.http.get(url, headers={"Transfer-Encoding": "chunked, identity"})
            if not resp:
                return
            if resp.status_code == 200:
                log_warn(logger, f"Server accepted ambiguous Transfer-Encoding on {url}")
                self.results.append(self._result(
                    url, "Request smuggling — server accepts ambiguous Transfer-Encoding header", "WARN",
                    detail=(
                        "A GET request with 'Transfer-Encoding: chunked, identity' (invalid per "
                        "RFC 7230) was accepted with HTTP 200. Servers that accept malformed TE "
                        "headers may mis-parse request body length, a prerequisite for TE.CL "
                        "request smuggling when a frontend proxy is present. "
                        "Fix: configure the server to return 400 Bad Request for non-standard "
                        "Transfer-Encoding values; use HTTP/2 where possible."
                    )
                ))
            # 400/501 = server correctly rejected the malformed header — good signal, no finding
        except Exception:
            pass
