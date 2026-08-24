"""
HTTP Compression Oracle (BREACH/CRIME) Scanner.

BREACH (Browser Reconnaissance and Exfiltration via Adaptive Compression of
Hypertext) is an attack that exploits HTTP compression combined with TLS to
extract secrets from HTTPS responses.

Attack conditions (all three must be true):
  1. HTTPS connection (required for timing attack)
  2. HTTP response compression enabled (gzip, br, zstd, deflate)
  3. Secret (CSRF token, session identifier, auth token) appears in response body

When all conditions are met, an attacker who can inject content into the same
HTTPS response and observe the compressed size can iteratively guess the secret
one character at a time.

CRIME (Compression Ratio Info-leak Made Easy) is the TLS-level variant; BREACH
works at the HTTP application layer.

This scanner passively detects BREACH conditions without attempting extraction:
  1. Is the response compressed?
  2. Does the response body contain a CSRF token pattern?
  3. Does the Content-Type suggest an HTML page (not a static asset)?
  4. Is the target HTTPS?

Reference: https://breachattack.com/
CVE-2013-3587
CWE-311: Missing Encryption of Sensitive Data (precondition)
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_COMPRESSION_ENCODINGS = {"gzip", "br", "brotli", "deflate", "zstd", "compress"}

_CSRF_TOKEN_RE = re.compile(
    r'(?:'
    r'name=["\'](?:csrf|_token|authenticity_token|csrftoken|csrf_token|__RequestVerificationToken)["\'][^>]*value=["\']([a-zA-Z0-9_+/=-]{20,})["\']'
    r'|value=["\']([a-zA-Z0-9_+/=-]{20,})["\'][^>]*name=["\'](?:csrf|_token|authenticity_token|csrftoken|csrf_token|__RequestVerificationToken)["\']'
    r'|"csrfToken"\s*:\s*"([a-zA-Z0-9_+/=-]{20,})"'
    r'|window\.__CSRF_TOKEN__\s*=\s*["\']([a-zA-Z0-9_+/=-]{20,})["\']'
    r')',
    re.I
)
_SESSION_IN_BODY_RE = re.compile(
    r'(?:'
    r'"sessionId"\s*:\s*"[a-zA-Z0-9]{20,}"'
    r'|"session_token"\s*:\s*"[a-zA-Z0-9]{20,}"'
    r'|var\s+session\s*=\s*["\'][a-zA-Z0-9]{20,}["\']'
    r')',
    re.I
)
_HTML_CT_RE = re.compile(r'text/html|application/xhtml', re.I)
_API_CT_RE  = re.compile(r'application/json|text/plain', re.I)


class CompressionOracleScanner(BaseScanner):
    """Detect BREACH/CRIME attack preconditions on HTTPS pages."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed = urlparse(url)

        if parsed.scheme != "https":
            self.results.append(self._result(
                url, "Compression oracle — target is not HTTPS (BREACH requires TLS)", "PASS",
                detail="BREACH requires an HTTPS connection. HTTP targets are not vulnerable."
            ))
            return self.results

        try:
            resp = self.http.get(url, headers={"Accept-Encoding": "gzip, br, deflate, zstd"})
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "Compression oracle — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        content_encoding = resp.headers.get("content-encoding", "").lower()
        ct = resp.headers.get("content-type", "").lower()
        body = resp.text or ""

        encodings_present = {
            enc for enc in _COMPRESSION_ENCODINGS if enc in content_encoding
        }

        if not encodings_present:
            log_pass(logger, f"No HTTP compression detected at {url}")
            self.results.append(self._result(
                url, "Compression oracle — no HTTP compression detected", "PASS",
                detail=(
                    "The response does not include Content-Encoding with a compression scheme. "
                    "BREACH attack conditions are not met."
                )
            ))
            return self.results

        if _API_CT_RE.search(ct) and not _HTML_CT_RE.search(ct):
            log_pass(logger, f"Compression on API/JSON at {url} — no user-controlled injection")
            self.results.append(self._result(
                url,
                f"Compression oracle — compression ({', '.join(encodings_present)}) on API (lower risk)",
                "PASS",
                detail=(
                    f"HTTP compression ({', '.join(encodings_present)}) is active on this API endpoint. "
                    "BREACH requires that an attacker can inject content into the same compressed response. "
                    "For pure JSON APIs without user-controlled reflected content, risk is lower."
                )
            ))
            return self.results

        has_csrf = bool(_CSRF_TOKEN_RE.search(body))
        has_session_in_body = bool(_SESSION_IN_BODY_RE.search(body))

        if has_csrf or has_session_in_body:
            secret_type = "CSRF token" if has_csrf else "session identifier"
            log_fail(logger, f"BREACH conditions met at {url}: {secret_type} in compressed HTTPS response")
            self.results.append(self._result(
                url,
                f"Compression oracle — BREACH: {secret_type} in compressed HTTPS response",
                "FAIL",
                detail=(
                    f"HTTPS response uses {', '.join(encodings_present)} compression and "
                    f"contains a {secret_type} in the response body. "
                    "If an attacker can inject content into the same response (e.g., via a "
                    "query parameter reflected in the page), they can perform a BREACH attack "
                    "to extract the secret by observing compressed response sizes. "
                    "Fix: (1) disable compression on pages containing secrets, or "
                    "(2) add random padding to the response to defeat compression oracle, or "
                    "(3) use length-hiding (padding) in TLS. "
                    "Mitigations: CSRF tokens that change per response defeat BREACH; "
                    "SameSite cookies reduce the attacker's ability to inject requests."
                )
            ))
        else:
            log_warn(logger, f"HTTP compression on HTTPS page at {url} (no detected secrets in body)")
            self.results.append(self._result(
                url,
                f"Compression oracle — compression ({', '.join(encodings_present)}) on HTTPS page",
                "WARN",
                detail=(
                    f"HTTP compression ({', '.join(encodings_present)}) is active on this HTTPS page. "
                    "BREACH attacks require a secret in the compressed response. No CSRF tokens "
                    "or session identifiers were detected in the current response, but they may "
                    "appear on other pages or for authenticated users. "
                    "Fix: review pages containing CSRF tokens or user session data and consider "
                    "disabling compression on those responses, or using random token padding."
                )
            ))

        return self.results
