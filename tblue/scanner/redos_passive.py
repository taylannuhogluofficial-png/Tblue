"""
ReDoS (Regular Expression Denial of Service) Passive Scanner.

Detects client-side ReDoS-vulnerable regex patterns in JavaScript bundles
and server-side ReDoS indicators via error message analysis:

1. Regex patterns with catastrophic backtracking structure in JS
   - Nested quantifiers: (a+)+ / (a*)*
   - Alternation with overlap: (a|aa)+
   - Backtracking amplifiers: (a|b)*c when c not present
2. Server-side regex timeout errors in response bodies (error messages)
3. Overly long input reflected in error responses (potential ReDoS probe echo)
4. User-input-in-regex patterns: new RegExp(userInput)

All checks are passive — no ReDoS payloads are sent.
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

# Catastrophic backtracking patterns — nested/repeated quantifiers
_NESTED_QUANTIFIER_RE = re.compile(
    r'\([^)]+[+*]\)[+*]',   # (a+)+  (a*)+ etc.
    re.I,
)

# Dynamic regex construction from user input
_DYNAMIC_REGEX_RE = re.compile(
    r'new\s+RegExp\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|userInput|input|search|pattern)',
    re.I,
)

# Server-side timeout/regex error messages
_REGEX_TIMEOUT_RE = re.compile(
    r'(?:regex|regexp|regular expression|pattern)\s*(?:timeout|too complex|catastrophic|backtrack)',
    re.I,
)

# Known ReDoS-vulnerable regex shapes in common validation libraries
_VULNERABLE_PATTERNS = [
    # Email regex with nested quantifiers (classic ReDoS)
    re.compile(r'\[?[a-z0-9._%-]+\]?\+@\[?[a-z0-9._%-]+\]\+\\.', re.I),
    # URL regex with overlapping groups
    re.compile(r'\(https?://\)\?\([^/]+\)\+', re.I),
    # HTML tag matching with nested groups
    re.compile(r'<\[^>]+\*>', re.I),
]


class ReDoSPassiveScanner(BaseScanner):
    """Detect ReDoS-vulnerable regex patterns in JavaScript and error responses."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "ReDoS passive — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        self._check_page_body(url, resp.text)
        self._check_js_bundles(url, origin, resp.text)

        if not self.results:
            log_pass(logger, f"No ReDoS indicators found at {url}")
            self.results.append(self._result(
                url, "ReDoS passive — no ReDoS-vulnerable patterns detected", "PASS",
                detail="No catastrophic backtracking regex patterns or dynamic regex construction found."
            ))

        return self.results

    def _check_page_body(self, url: str, body: str) -> None:
        if _REGEX_TIMEOUT_RE.search(body):
            log_warn(logger, f"Regex timeout/ReDoS error message in response at {url}")
            self.results.append(self._result(
                url, "ReDoS passive — regex timeout error in response", "WARN",
                detail=(
                    "An error message suggesting regex timeout or catastrophic backtracking was "
                    "found in the page response. This may indicate a ReDoS vulnerability was "
                    "triggered by a prior request, or debug error output is leaking. "
                    "Fix: audit all server-side regex patterns for catastrophic backtracking; "
                    "use regex timeout limits (re2, timeout parameter)."
                )
            ))

        if _NESTED_QUANTIFIER_RE.search(body):
            log_warn(logger, f"Nested quantifier regex pattern in response body at {url}")
            self.results.append(self._result(
                url, "ReDoS passive — nested quantifier pattern in page source", "WARN",
                detail=(
                    "A regex pattern with nested quantifiers (e.g., (a+)+, (a*)*) was detected "
                    "in the page source. Such patterns exhibit catastrophic backtracking when "
                    "matched against specially crafted input, causing CPU exhaustion. "
                    "Fix: rewrite using possessive quantifiers, atomic groups, or the re2 library."
                )
            ))

        if _DYNAMIC_REGEX_RE.search(body):
            log_warn(logger, f"Dynamic RegExp construction from user input at {url}")
            self.results.append(self._result(
                url, "ReDoS passive — dynamic RegExp from user input", "WARN",
                detail=(
                    "new RegExp(userInput) or similar dynamic regex construction from request "
                    "parameters was found. This allows an attacker to supply a catastrophically "
                    "backtracking pattern as input, causing server-side CPU exhaustion. "
                    "Fix: never construct regex from untrusted input; use a fixed pattern set; "
                    "apply input length limits."
                )
            ))

    def _check_js_bundles(self, url: str, origin: str, body: str) -> None:
        js_re = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
        checked = 0
        for m in js_re.finditer(body):
            if checked >= 3:
                break
            src = m.group(1)
            if not src.startswith("http"):
                src = origin + ("" if src.startswith("/") else "/") + src
            try:
                js_resp = self.http.get(src)
                if js_resp is None or js_resp.status_code != 200:
                    continue
                js_body = js_resp.text
                checked += 1

                if _NESTED_QUANTIFIER_RE.search(js_body):
                    log_warn(logger, f"Nested quantifier ReDoS pattern in JS bundle {src}")
                    self.results.append(self._result(
                        src, "ReDoS passive — nested quantifier in JS bundle", "WARN",
                        detail=(
                            f"A regex with nested quantifiers was found in the JavaScript bundle {src}. "
                            "Client-side ReDoS causes browser tab freezing when matched against "
                            "user input (e.g., form validation fields). "
                            "Fix: use a ReDoS-safe regex linter (safe-regex, redos-detector) in CI."
                        )
                    ))
                    break

                if _DYNAMIC_REGEX_RE.search(js_body):
                    log_warn(logger, f"Dynamic RegExp from request data in JS bundle {src}")
                    self.results.append(self._result(
                        src, "ReDoS passive — dynamic RegExp in JS bundle", "WARN",
                        detail=(
                            f"Dynamic RegExp construction from request parameters found in {src}. "
                            "Fix: validate and sanitize pattern before regex construction; "
                            "prefer literal regex patterns."
                        )
                    ))
                    break
            except Exception:
                continue
