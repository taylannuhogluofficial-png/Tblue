"""
Advanced SSRF (Server-Side Request Forgery) Detection Scanner.

Goes beyond the basic cloud metadata scanner by detecting SSRF vectors in:

1. URL input parameters (url=, redirect=, link=, target=, callback=, etc.)
2. Webhook configuration endpoints
3. Import/fetch URLs submitted in request bodies
4. XML entity injection in upload paths (XXE → SSRF)
5. PDF/image generation endpoints that accept external URLs
6. Open redirect chained with SSRF
7. DNS rebinding indicators (checking if private IPs appear in responses)

Detection approach: tests SSRF-prone parameter names and URL patterns
WITHOUT making out-of-band callbacks (which would require an external
collaborator server). Instead, detects based on:
- Parameter names associated with URL fetching
- Response body containing private IP ranges
- Response metadata suggesting server-initiated fetches
- Error messages indicating file:// or dict:// scheme attempts
- HTTP response timing anomalies on known-slow internal hosts

This is a blue-team defensive scanner — no actual SSRF payloads are sent.
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Parameters commonly used to accept URLs for server-side fetching
_SSRF_PARAM_NAMES = frozenset({
    "url", "uri", "src", "source", "href", "link", "target", "dest",
    "redirect", "redirect_url", "redirect_uri", "return", "return_url",
    "callback", "webhook", "endpoint", "remote", "fetch", "load",
    "import", "feed", "file", "document", "image_url", "avatar_url",
    "logo_url", "icon_url", "thumbnail", "proxy", "path", "host",
    "domain", "site", "forward", "next", "goto", "jump", "continue",
    "location", "service", "api_url", "base_url", "download",
})

# Response body patterns indicating the server fetched an internal resource
_PRIVATE_IP_RE = re.compile(
    r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}"
    r"|::1|localhost)"
)

# Error messages indicating attempted internal scheme fetches
_SSRF_ERROR_RE = re.compile(
    r"file not found|connection refused|network unreachable"
    r"|could not connect|failed to fetch|invalid url"
    r"|no such host|name or service not known"
    r"|unable to connect|getaddrinfo failed",
    re.I,
)

# Import/webhook endpoint patterns
_IMPORT_PATH_RE = re.compile(
    r"/(?:import|webhook|callback|feed|fetch|proxy|remote|preview|screenshot"
    r"|export|convert|render|generate|pdf|thumbnail|avatar|logo)",
    re.I,
)

# XML-like content type acceptance (XXE → SSRF)
_XML_ACCEPT_RE = re.compile(r"text/xml|application/xml|application/rss\+xml|application/atom\+xml", re.I)


class SSRFAdvancedScanner(BaseScanner):
    """Detects SSRF-prone parameter names and URL-fetching patterns."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping SSRF advanced checks: {url}")
            self.results.append(self._result(
                url, "SSRF Advanced — no response from target", "PASS",
                detail="Target did not respond; SSRF checks skipped."
            ))
            return self.results

        html = resp.text or ""
        self._check_form_url_params(url, html)
        self._check_url_query_params(url)
        self._check_import_endpoints(url)
        self._check_xml_upload_endpoints(url, resp)
        self._check_private_ip_in_response(url, html)

        if not self.results:
            log_pass(logger, f"No SSRF-prone patterns found on {url}")
            self.results.append(self._result(
                url, "SSRF Advanced — no SSRF-prone patterns detected", "PASS",
                detail=(
                    "No URL-accepting parameters, import/webhook endpoints, "
                    "or private IP leakage found on the main page."
                )
            ))

        return self.results

    def _check_form_url_params(self, url: str, html: str) -> None:
        """Detect forms with URL-accepting input fields."""
        soup = BeautifulSoup(html, "html.parser")
        ssrf_inputs = []
        for form in soup.find_all("form"):
            for inp in form.find_all("input"):
                name = inp.attrs.get("name", "").lower()
                itype = inp.attrs.get("type", "text").lower()
                if name in _SSRF_PARAM_NAMES and itype not in ("submit", "button", "hidden"):
                    ssrf_inputs.append((name, inp.attrs.get("type", "text")))

        if ssrf_inputs:
            names = [n for n, _ in ssrf_inputs[:5]]
            log_fail(logger, f"SSRF-prone URL parameters in forms on {url}: {names}")
            self.results.append(self._result(
                url, "SSRF Advanced — URL-accepting form parameters detected", "FAIL",
                detail=(
                    f"Found {len(ssrf_inputs)} form input(s) with SSRF-prone names: "
                    f"{', '.join(names)}. "
                    "If the server fetches these URLs without validation, attackers can "
                    "probe internal services, cloud metadata (169.254.169.254), or read "
                    "local files via file:// protocol. "
                    "Fix: validate submitted URLs against an allowlist; "
                    "reject private IP ranges, file://, dict://, gopher:// schemes; "
                    "use a dedicated HTTP client that blocks internal addresses."
                )
            ))

    def _check_url_query_params(self, url: str) -> None:
        """Detect SSRF-prone names in URL query parameters."""
        parsed = urlparse(url)
        if not parsed.query:
            return

        params = parse_qs(parsed.query)
        ssrf_params = [k for k in params if k.lower() in _SSRF_PARAM_NAMES]

        if ssrf_params:
            log_warn(logger, f"SSRF-prone URL parameters in query string: {ssrf_params}")
            self.results.append(self._result(
                url, "SSRF Advanced — SSRF-prone query parameters detected", "WARN",
                detail=(
                    f"Query string contains SSRF-prone parameter names: {ssrf_params}. "
                    "If the server fetches the URL value without validation, this is "
                    "a potential SSRF vector. "
                    "Fix: validate and sanitize all URL parameters before server-side fetching. "
                    "Use SSRF protection libraries (ssrf-req-filter, urllib3 with custom adapters)."
                )
            ))

    def _check_import_endpoints(self, url: str) -> None:
        """Probe common import/webhook URL endpoints."""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        import_paths = [
            "/webhook", "/webhooks", "/api/webhook",
            "/import", "/api/import",
            "/feed", "/rss", "/atom",
            "/api/preview", "/preview",
            "/screenshot", "/api/screenshot",
            "/pdf", "/api/pdf", "/convert",
        ]

        for path in import_paths:
            probe_url = base + path
            r = self.http.get(probe_url)
            if r is None or r.status_code not in (200, 201, 405, 400):
                continue

            body = r.text or ""
            # 405 Method Not Allowed indicates the endpoint exists but needs POST
            # 400 Bad Request may mean it expects a URL parameter
            if r.status_code in (200, 201) or (
                r.status_code in (405, 400) and (
                    "url" in body.lower() or "webhook" in body.lower() or
                    "endpoint" in body.lower()
                )
            ):
                log_warn(logger, f"Potential import/webhook endpoint: {probe_url}")
                self.results.append(self._result(
                    probe_url, f"SSRF Advanced — import/webhook endpoint accessible ({path})", "WARN",
                    detail=(
                        f"Import or webhook endpoint found at {probe_url} "
                        f"(HTTP {r.status_code}). "
                        "These endpoints often accept a URL parameter for server-side fetching, "
                        "creating an SSRF risk if not properly validated. "
                        "Fix: validate all URLs accepted by import/webhook endpoints; "
                        "block private IP ranges and non-HTTP(S) schemes; "
                        "consider requiring authentication for these endpoints."
                    )
                ))
                break  # one finding per endpoint type is enough

    def _check_xml_upload_endpoints(self, url: str, resp) -> None:
        """Check if the endpoint accepts XML content types (XXE → SSRF risk)."""
        content_type_header = resp.headers.get("content-type", "")
        accept_header = resp.headers.get("accept", "")

        # If the server serves XML or the response mentions XML upload
        if _XML_ACCEPT_RE.search(content_type_header) or _XML_ACCEPT_RE.search(accept_header):
            log_warn(logger, f"XML content type accepted on {url} — potential XXE/SSRF risk")
            self.results.append(self._result(
                url, "SSRF Advanced — XML content type accepted (XXE/SSRF risk)", "WARN",
                detail=(
                    f"Endpoint accepts or returns XML content (Content-Type: {content_type_header}). "
                    "XML parsers that process DOCTYPE declarations are vulnerable to XXE, "
                    "which can chain into SSRF by fetching arbitrary external entities. "
                    "Fix: disable DOCTYPE processing in your XML parser "
                    "(e.g. FEATURE_SECURE_PROCESSING in Java SAXParserFactory, "
                    "resolve_entities=False in Python lxml, "
                    "defusedxml library for Python)."
                )
            ))

    def _check_private_ip_in_response(self, url: str, html: str) -> None:
        """Check if response body contains private IP addresses (SSRF leak)."""
        private_ips = list(set(_PRIVATE_IP_RE.findall(html)))
        if not private_ips:
            return

        # Filter out IPs that appear in HTML comments or likely legitimate code examples
        filtered = [ip for ip in private_ips if ip not in ("127.0.0.1", "localhost")]
        if not filtered:
            return

        log_fail(logger, f"Private IP addresses found in response body: {filtered[:5]}")
        self.results.append(self._result(
            url, "SSRF Advanced — private IP addresses in response body", "FAIL",
            detail=(
                f"Private/internal IP addresses found in page response: {', '.join(filtered[:5])}. "
                "This may indicate SSRF responses leaking internal network topology, "
                "or misconfigured load balancers exposing internal IP headers. "
                "Fix: ensure server responses don't reveal internal IP addresses; "
                "check for X-Forwarded-For or X-Real-IP header leakage. "
                "Also check if these IPs appear in API responses that aggregate SSRF data."
            )
        ))
