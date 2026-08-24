"""
CRLF Injection / HTTP Response Splitting Scanner.

Injects Carriage Return + Line Feed (\\r\\n) sequences into URL parameters and
headers to detect whether the server echoes them back unsanitized in response headers.

If CR+LF sequences reach HTTP headers, an attacker can:
- Inject arbitrary response headers (e.g., Set-Cookie)
- Split the HTTP response, injecting a fake second response body
- Execute XSS via injected headers (e.g., Location with javascript:)
- Poison caches with injected content

Strictly passive/read-only: only sends probes with harmless marker strings;
never attempts actual exploitation or data exfiltration.

CWE-93: Improper Neutralization of CRLF Sequences in HTTP Headers
"""

from typing import Any, Dict, List
from urllib.parse import urlencode, urlparse, parse_qs, quote

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# CRLF probe payloads — various encodings an attacker might try
_CRLF_PAYLOADS = [
    "%0d%0a",          # Standard URL-encoded CRLF
    "%0D%0A",          # Uppercase hex
    "%0d%0aX-Injected:%20test",     # With header name
    "%0D%0AX-Injected:%20test",     # Uppercase with header
    "\r\n",            # Literal (handled by requests as-is)
    "%E5%98%8A%E5%98%8D",   # Unicode CRLF bypass (U+560A U+560D)
]

# Marker to look for in response headers after injection
_INJECT_MARKER = "x-injected"

# Common redirect/location parameters where CRLF is most dangerous
_REDIRECT_PARAMS = frozenset({
    "next", "url", "redirect", "redirect_url", "return", "returnurl",
    "return_url", "goto", "location", "continue", "dest", "destination",
    "ref", "referer", "back", "target", "forward",
})


class CRLFInjectionScanner(BaseScanner):
    """Detects CRLF injection / HTTP response splitting vulnerabilities."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping CRLF injection checks: {url}")
            self.results.append(self._result(
                url, "CRLF injection — no response", "PASS",
                detail="Target did not respond; CRLF injection checks skipped."
            ))
            return self.results

        self._check_url_params(url)
        self._check_redirect_params(url)

        if not self.results:
            log_pass(logger, f"No CRLF injection found on {url}")
            self.results.append(self._result(
                url, "CRLF injection — no injection points found", "PASS",
                detail=(
                    "No CRLF sequences were reflected in response headers. "
                    "URL parameters and common redirect parameters appear to be sanitized."
                )
            ))

        return self.results

    def _check_url_params(self, url: str) -> None:
        """Test CRLF injection in existing URL query parameters."""
        parsed = urlparse(url)
        if not parsed.query:
            return

        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return

        for param_name in list(params.keys()):
            for payload in _CRLF_PAYLOADS[:3]:  # Limit probes per param
                probe_url = self._build_probe_url(url, param_name, payload)
                r = self.http.get(probe_url)
                if r is None:
                    continue
                if self._headers_contain_injection(r):
                    log_fail(logger, f"CRLF injection via URL param '{param_name}': {url}")
                    self.results.append(self._result(
                        url,
                        f"CRLF injection — response splitting via parameter '{param_name}'",
                        "FAIL",
                        detail=(
                            f"CRLF sequence in URL parameter '{param_name}' was reflected in "
                            f"response headers (payload: {payload!r}). "
                            "This allows an attacker to inject arbitrary HTTP headers, "
                            "set cookies, redirect to attacker pages, or split the response "
                            "to inject a fake second HTTP response (cache poisoning). "
                            "Fix: strip or encode CR (\\r, %0d) and LF (\\n, %0a) from all "
                            "values used in HTTP header context. Never reflect user input "
                            "directly into response headers."
                        )
                    ))
                    return  # One confirmed CRLF is enough to report

    def _check_redirect_params(self, url: str) -> None:
        """Test CRLF injection in common redirect parameters added to the URL."""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for param in _REDIRECT_PARAMS:
            for payload in _CRLF_PAYLOADS[:2]:  # 2 payloads per redirect param
                test_value = f"https://example.com/{payload}X-Injected:%20test"
                probe_url = f"{base}?{param}={quote(test_value, safe=':/.')}"
                r = self.http.get(probe_url)
                if r is None:
                    continue

                # Check for CRLF in Location or Set-Cookie
                if self._headers_contain_injection(r):
                    log_fail(logger, f"CRLF injection via redirect param '{param}': {url}")
                    self.results.append(self._result(
                        url,
                        f"CRLF injection — response splitting via redirect parameter '{param}'",
                        "FAIL",
                        detail=(
                            f"CRLF sequence in redirect parameter '{param}' was reflected in "
                            f"response headers (payload: {payload!r}). "
                            "Redirect parameters are especially dangerous for CRLF injection "
                            "because they are commonly reflected into Location headers. "
                            "An attacker can inject Set-Cookie headers to hijack sessions, "
                            "or poison HTTP caches with injected fake responses. "
                            "Fix: validate redirect URLs against an allowlist of trusted domains; "
                            "strip CR and LF characters before using values in header context."
                        )
                    ))
                    return

                # Also check for the marker in the response body (header injection → body split)
                body = r.text or ""
                if _INJECT_MARKER in body.lower():
                    log_warn(logger, f"CRLF marker reflected in body via param '{param}': {url}")
                    self.results.append(self._result(
                        url,
                        f"CRLF injection — marker reflected in response body via '{param}'",
                        "WARN",
                        detail=(
                            f"CRLF probe payload was found reflected in the response body "
                            f"via parameter '{param}'. This may indicate partial sanitization "
                            "that strips the header injection but not the LF. "
                            "Full response splitting may still be possible with different encodings. "
                            "Fix: sanitize all CR and LF characters from user-controlled values."
                        )
                    ))
                    return

    def _build_probe_url(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [f"test{payload}X-Injected:%20test"]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return parsed._replace(query=new_query).geturl()

    def _headers_contain_injection(self, resp) -> bool:
        """Check if injected marker appears in any response header name or value."""
        for header_name, header_value in resp.headers.items():
            if _INJECT_MARKER in header_name.lower():
                return True
            if _INJECT_MARKER in header_value.lower():
                return True
        return False
