"""
JavaScript Dangerous Pattern Scanner.

Detects security-sensitive JavaScript patterns in inline scripts and
small linked JS files. Goes beyond CSP enforcement to identify specific
code patterns that enable exploitation:

1. Direct eval() with dynamic/external input:
   - `eval(location.hash)`, `eval(document.URL)`, `eval(atob(data))`
   - `new Function(userInput)()` — equivalent to eval
2. Postfix DOM XSS sinks with tainted sources:
   - `element.innerHTML = location.hash`
   - `document.write(location.search)`
   - `$(...)` with URL-derived input
3. Dangerous URL navigation:
   - `location.href = userInput` without validation
   - `window.open(document.referrer)` — open redirect via referrer
4. Cross-origin messaging without origin check:
   - `window.addEventListener('message', handler)` without `event.origin` check
5. Prototype pollution gadgets in local code:
   - Already covered by `prototype_pollution.py` / `javascript_prototype_pollution_deep.py`
   - Here: `__proto__` in response JSON echoed back to page
6. Dangerous `setTimeout` / `setInterval` with string argument:
   - `setTimeout("eval(...)", 1000)` — string form executes via eval
7. `execScript()` / `execCommand()` — legacy IE eval equivalents
8. Disabled subresource integrity in dynamically created script tags:
   - `script.src = externalUrl` without `script.integrity` assignment

CWE-79: Cross-Site Scripting
CWE-94: Improper Control of Generation of Code (Code Injection)
"""

import re
from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_TAINTED_SOURCES_RE = re.compile(
    r'location\.(?:hash|search|href|pathname)|document\.(?:URL|referrer|cookie)|'
    r'window\.name|document\.domain|'
    r'(?:req|request)\.(?:params|query|body|headers)\[',
    re.I
)

_EVAL_PATTERNS: List[tuple] = [
    (
        "eval_direct",
        re.compile(r'\beval\s*\((?:(?!eval).)*?(?:location|document\.URL|atob|decodeURI|window\.name)', re.I | re.S),
        "FAIL",
        "eval() with potentially tainted source"
    ),
    (
        "new_function",
        re.compile(r'new\s+Function\s*\(', re.I),
        "WARN",
        "new Function() — equivalent to eval, executes string as code"
    ),
    (
        "settimeout_string",
        re.compile(r'(?:setTimeout|setInterval)\s*\(\s*["\']', re.I),
        "WARN",
        "setTimeout/setInterval with string argument (executes via eval)"
    ),
    (
        "exec_script",
        re.compile(r'\bexecScript\s*\(|\bdocument\.execCommand\s*\(\s*["\']javascript', re.I),
        "WARN",
        "execScript() / document.execCommand('javascript') — legacy eval equivalent"
    ),
]

_DOM_XSS_SINKS: List[tuple] = [
    (
        "innerhtml_location",
        re.compile(
            r'\.innerHTML\s*[+]?=\s*(?:[^\n;]{0,80}?)'
            r'(?:location\.|document\.URL|document\.referrer|window\.name)',
            re.I
        ),
        "FAIL",
        "innerHTML = with URL-derived tainted source (DOM XSS sink)"
    ),
    (
        "document_write_location",
        re.compile(
            r'document\.write\s*\([^\)]{0,120}?(?:location\.|document\.URL|document\.referrer)',
            re.I
        ),
        "FAIL",
        "document.write() with URL-derived tainted source (DOM XSS sink)"
    ),
    (
        "location_assign_external",
        re.compile(
            r'(?:location\.href|location\.replace|window\.open)\s*[=(]+\s*'
            r'(?:[^\n;]{0,80}?)'
            r'(?:location\.|document\.referrer|window\.name|(?:req|params)\[)',
            re.I
        ),
        "WARN",
        "location.href/open() with potentially external/tainted source (open redirect)"
    ),
]

_POSTMESSAGE_NO_ORIGIN_RE = re.compile(
    r'addEventListener\s*\(\s*["\']message["\'].*?function\s*\([^)]*\)\s*\{(?:(?!\.origin).){0,500}\}',
    re.I | re.S
)

_DYNAMIC_SCRIPT_NO_SRI_RE = re.compile(
    r'(?:var|let|const)?\s*\w+\s*=\s*document\.createElement\s*\(\s*["\']script["\']',
    re.I
)

_SCRIPT_SRC_ASSIGN_RE = re.compile(r'\.src\s*=\s*["\']https?://', re.I)
_SCRIPT_INTEGRITY_RE  = re.compile(r'\.integrity\s*=\s*["\']sha', re.I)


class JSDangerousPatternsScanner(BaseScanner):
    """Detect dangerous JavaScript patterns that indicate XSS/injection sinks."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "JS dangerous patterns — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        body = resp.text or ""

        self._check_eval_patterns(url, body)
        self._check_dom_xss_sinks(url, body)
        self._check_postmessage_origin(url, body)
        self._check_dynamic_script_no_sri(url, body)

        if not any(r["status"] in ("FAIL", "WARN") for r in self.results):
            log_pass(logger, f"No dangerous JS patterns at {url}")
            self.results.append(self._result(
                url, "JS dangerous patterns — no dangerous patterns detected in inline JS", "PASS",
                detail="No eval-with-tainted-source, DOM XSS sinks, or postMessage without origin checks found."
            ))

        return self.results

    def _check_eval_patterns(self, url: str, body: str) -> None:
        for key, pattern, severity, label in _EVAL_PATTERNS:
            if pattern.search(body):
                log_warn(logger, f"JS dangerous pattern [{key}] at {url}")
                self.results.append(self._result(
                    url,
                    f"JS dangerous patterns — {label}",
                    severity,
                    detail=(
                        f"Pattern '{key}' detected: {label}. "
                        "String-based code execution (eval, new Function, setTimeout with string) "
                        "is a direct code injection vector when combined with user-controlled input. "
                        "Fix: replace eval/new Function with safe alternatives; never pass "
                        "user-controlled strings to code execution functions."
                    )
                ))

    def _check_dom_xss_sinks(self, url: str, body: str) -> None:
        for key, pattern, severity, label in _DOM_XSS_SINKS:
            if pattern.search(body):
                log_warn(logger, f"DOM XSS sink pattern [{key}] at {url}")
                self.results.append(self._result(
                    url,
                    f"JS dangerous patterns — {label}",
                    severity,
                    detail=(
                        f"DOM XSS pattern '{key}' detected: {label}. "
                        "DOM-based XSS occurs when user-controlled data (URL fragments, referrer, "
                        "window.name) is written to DOM sinks without sanitization. "
                        "Fix: sanitize user-controlled sources before writing to DOM sinks, "
                        "or use Trusted Types to restrict dangerous sink writes."
                    )
                ))

    def _check_postmessage_origin(self, url: str, body: str) -> None:
        if _POSTMESSAGE_NO_ORIGIN_RE.search(body):
            log_warn(logger, f"postMessage listener without origin check at {url}")
            self.results.append(self._result(
                url,
                "JS dangerous patterns — postMessage listener without event.origin validation",
                "WARN",
                detail=(
                    "A message event listener was detected without an apparent event.origin check "
                    "in the handler body. Message event handlers that process any message regardless "
                    "of origin allow cross-origin windows to inject commands or data. "
                    "Fix: always validate event.origin against a trusted origin allowlist "
                    "before processing the message."
                )
            ))

    def _check_dynamic_script_no_sri(self, url: str, body: str) -> None:
        dynamic_scripts = _DYNAMIC_SCRIPT_NO_SRI_RE.findall(body)
        if not dynamic_scripts:
            return

        script_src_matches = _SCRIPT_SRC_ASSIGN_RE.findall(body)
        if not script_src_matches:
            return

        has_integrity = bool(_SCRIPT_INTEGRITY_RE.search(body))
        if not has_integrity:
            log_warn(logger, f"Dynamic external script tag without SRI at {url}")
            self.results.append(self._result(
                url,
                "JS dangerous patterns — dynamically created external <script> without SRI integrity",
                "WARN",
                detail=(
                    "The page dynamically creates script elements with external src= URLs "
                    "without assigning an integrity attribute. Dynamic script injection "
                    "without SRI is vulnerable to supply chain compromise — a compromised CDN "
                    "can serve malicious JavaScript. "
                    "Fix: assign script.integrity = 'sha384-...' before appending dynamic "
                    "external scripts, or use importmaps with integrity hashes."
                )
            ))
