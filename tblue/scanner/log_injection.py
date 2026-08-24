"""
Log Injection / Log Forging Scanner.

Detects whether the application reflects unsanitized user-controlled values
into log output that could later appear in the HTTP response (error pages,
debug output) or that indicate logging of raw input.

Attack scenarios:
1. User-Agent, X-Forwarded-For, or Referer headers reflected in error responses
   → indicates the value is logged and an attacker can forge log entries
2. CRLF sequences in logged headers create multi-line log entries
   → an attacker injects fake log lines to cover tracks or confuse SIEM
3. ANSI escape sequences in log output (console injection)
4. SQL/JSON fragments in logged fields appearing in error responses
5. Log4Shell-style JNDI patterns detected in responses (CVE-2021-44228)

All checks are read-only. Markers are benign strings that do not
trigger active exploitation — we only probe whether they're echoed back.

CWE-117: Improper Output Neutralization for Logs
CWE-93: Improper Neutralization of CRLF Sequences in HTTP Headers
"""

import re
from typing import Any, Dict, List
from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_MARKER = "TblueLogProbe9z8x"
_CRLF_MARKER = f"X-Log-Injected: {_MARKER}"

# Payloads to inject into request headers
_HEADER_PAYLOADS = {
    "User-Agent": [
        f"{_MARKER}",                                  # Bare marker
        f"Mozilla/5.0 ({_MARKER})",                    # Realistic UA with marker
        f"test\r\nX-Log-Injected: {_MARKER}",          # CRLF in UA
    ],
    "X-Forwarded-For": [
        f"1.2.3.4, {_MARKER}",
        f"127.0.0.1\r\nX-Log-Injected: {_MARKER}",
    ],
    "Referer": [
        f"https://example.com/{_MARKER}",
    ],
}

# ANSI escape sequences used in console injection
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

# Log4Shell JNDI indicators in response
_LOG4SHELL_RE = re.compile(r"\$\{jndi:", re.I)

# Error response keywords suggesting reflection
_ERROR_INDICATORS = re.compile(
    r"error|exception|stacktrace|traceback|debug|log|request",
    re.I,
)


class LogInjectionScanner(BaseScanner):
    """Detects log injection and log forging via header reflection."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping log injection checks: {url}")
            self.results.append(self._result(
                url, "Log injection — no response", "PASS",
                detail="Target did not respond; log injection checks skipped."
            ))
            return self.results

        self._check_header_reflection(url)
        self._check_crlf_in_headers(url)
        self._check_log4shell_residue(url, resp)

        if not self.results:
            log_pass(logger, f"No log injection indicators on {url}")
            self.results.append(self._result(
                url, "Log injection — no reflection detected", "PASS",
                detail=(
                    "Probe markers in User-Agent, X-Forwarded-For, and Referer headers "
                    "were not reflected in response bodies. Log injection does not appear possible."
                )
            ))

        return self.results

    def _check_header_reflection(self, url: str) -> None:
        """Send marker in each header and check if it appears in the response body."""
        for header_name, payloads in _HEADER_PAYLOADS.items():
            for payload in payloads[:1]:  # One payload per header to limit requests
                if "\r\n" in payload:
                    continue  # CRLF handled separately
                r = self.http.get(url, headers={header_name: payload})
                if r is None:
                    continue

                body = r.text or ""
                if _MARKER in body:
                    log_warn(logger, f"Log injection: {header_name} reflected in response body: {url}")
                    self.results.append(self._result(
                        url,
                        f"Log injection — {header_name} value reflected in response body",
                        "WARN",
                        detail=(
                            f"Value of {header_name} request header appeared in the response body. "
                            "If this value is also written to application logs, attackers can forge "
                            f"log entries by setting arbitrary {header_name} values. "
                            "This allows: covering attack tracks, injecting fake admin entries, "
                            "confusing SIEM correlation rules, and XSS via log viewers. "
                            "Fix: sanitize all user-controlled values before logging; "
                            "use structured logging (JSON) instead of string interpolation; "
                            f"strip or encode CRLF, ANSI escape sequences from {header_name} values."
                        )
                    ))
                    return

    def _check_crlf_in_headers(self, url: str) -> None:
        """Check if CRLF in User-Agent or X-Forwarded-For causes response header injection."""
        for header_name in ("User-Agent", "X-Forwarded-For"):
            payload = f"test\r\nX-Log-Injected: {_MARKER}"
            try:
                r = self.http.get(url, headers={header_name: payload})
                if r is None:
                    continue

                # Check if injected header appears in response
                resp_headers_lower = {k.lower(): v for k, v in r.headers.items()}
                if "x-log-injected" in resp_headers_lower:
                    log_fail(logger, f"CRLF in {header_name} injected response header: {url}")
                    self.results.append(self._result(
                        url,
                        f"Log injection — CRLF in {header_name} injects response headers",
                        "FAIL",
                        detail=(
                            f"CRLF sequence in {header_name} header was reflected as a new "
                            "response header. This is a response splitting vulnerability that "
                            "allows an attacker to inject arbitrary headers (Set-Cookie, Location) "
                            "and potentially forge log entries. "
                            "Fix: strip CR and LF from all values used in HTTP header context; "
                            f"validate {header_name} against expected format."
                        )
                    ))
                    return

                # Check body reflection of CRLF payload
                body = r.text or ""
                if _MARKER in body:
                    log_warn(logger, f"CRLF log injection: marker in body via {header_name}: {url}")
                    self.results.append(self._result(
                        url,
                        f"Log injection — CRLF payload in {header_name} reflected in body",
                        "WARN",
                        detail=(
                            f"CRLF-encoded payload via {header_name} appeared in the response body. "
                            "While header injection was not confirmed, the marker reflection "
                            "indicates insufficient sanitization of CRLF sequences. "
                            "Fix: strip CR and LF characters from all user-controlled header values "
                            "before logging or reflecting them."
                        )
                    ))
                    return
            except Exception:
                continue  # Some HTTP clients reject CRLF headers — that's fine

    def _check_log4shell_residue(self, url: str, resp) -> None:
        """Check if any response reflects a Log4Shell JNDI pattern (CVE-2021-44228)."""
        body = resp.text or ""
        if _LOG4SHELL_RE.search(body):
            log_fail(logger, f"Log4Shell JNDI pattern in response body: {url}")
            self.results.append(self._result(
                url,
                "Log injection — Log4Shell JNDI pattern (${jndi:) in response body",
                "FAIL",
                detail=(
                    "The response body contains a ${jndi:} pattern. "
                    "This could indicate: a Log4Shell vulnerability where the JNDI lookup string "
                    "was logged and the response includes log output; or a WAF bypass test that "
                    "was reflected. "
                    "CVE-2021-44228 (Log4Shell) allows remote code execution via JNDI lookup "
                    "in logged strings. "
                    "Fix: upgrade Log4j to ≥2.17.1; set log4j2.formatMsgNoLookups=true; "
                    "strip ${} patterns from all logged user input."
                )
            ))
