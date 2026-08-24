"""
postMessage Security Scanner.

window.postMessage() is a cross-origin communication API that bypasses the
Same-Origin Policy. Misuse enables data theft and CSRF-equivalent attacks:

  1. Missing origin check in message handler — any page can send messages
     and trigger arbitrary actions (account takeover, data exfiltration)

  2. Wildcard target origin ('*') in postMessage() calls — sensitive data
     (tokens, PII) is broadcast to ALL frames on ALL origins

  3. Unsafe use of event.data without validation — if event.data is passed
     directly to innerHTML, eval(), or navigation functions, it becomes
     a cross-origin XSS vector

  4. opener.postMessage() — communication back to an opener window without
     origin verification

Real-world impact: PayPal, Shopify, Electron apps, browser extensions,
and SaaS OAuth flows have all had postMessage vulnerabilities.

This is STATIC ANALYSIS of inline scripts and same-origin JS files.
No active probing.

CWE-345: Insufficient Verification of Data Authenticity
CWE-346: Origin Validation Error
"""

import re
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_MAX_BODY = 512 * 1024
_MAX_JS   = 256 * 1024

# Patterns for postMessage issues
_PATTERNS: List[tuple] = [
    # Wildcard target origin: postMessage(data, '*')
    (re.compile(r'\.postMessage\s*\([^)]{0,200},\s*["\']?\*["\']?\s*\)', re.I | re.S), "WARN",
     "postMessage with wildcard origin ('*') — broadcasts message to all frames on all origins"),

    # addEventListener for 'message' without origin check
    # Look for the listener function body that does NOT contain 'origin' check
    (re.compile(
        r"addEventListener\s*\(\s*['\"]message['\"].*?\{(?![\s\S]{0,300}event\s*\.\s*origin)[\s\S]{0,300}\}",
        re.I | re.S
    ), "WARN",
     "message event listener without apparent origin validation — any cross-origin frame can trigger it"),

    # event.data used directly in innerHTML / eval / navigation
    (re.compile(r'innerHTML\s*=\s*event\s*\.\s*data', re.I), "FAIL",
     "event.data assigned to innerHTML — cross-origin postMessage can inject arbitrary HTML"),

    (re.compile(r'eval\s*\(\s*event\s*\.\s*data', re.I), "FAIL",
     "eval(event.data) — cross-origin postMessage becomes remote code execution"),

    (re.compile(r'location\s*(?:\.\s*href\s*=|\.assign\s*\()\s*event\s*\.\s*data', re.I), "FAIL",
     "location redirect from event.data — cross-origin postMessage can redirect to attacker URL"),

    # opener.postMessage without origin
    (re.compile(r'opener\s*\.\s*postMessage\s*\([^)]{0,200},\s*["\']?\*["\']?\s*\)', re.I), "WARN",
     "opener.postMessage('*') — leaks data to potentially untrusted opener window"),

    # parent.postMessage with wildcard
    (re.compile(r'parent\s*\.\s*postMessage\s*\([^)]{0,200},\s*["\']?\*["\']?\s*\)', re.I), "WARN",
     "parent.postMessage('*') — broadcasts to parent frame regardless of origin"),

    # source.postMessage reply without saving origin
    (re.compile(r'event\s*\.\s*source\s*\.\s*postMessage\s*\([^)]{0,200},\s*["\']?\*["\']?\s*\)', re.I), "WARN",
     "event.source.postMessage('*') — reply sent to any origin, leaks response data"),
]

_SCRIPT_RE     = re.compile(r'<script[^>]*>(.*?)</script>', re.I | re.S)
_EXT_SCRIPT_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)


def _scan_js(js_text: str, source_id: str) -> List[Dict]:
    findings = []
    seen = set()
    for pattern, severity, description in _PATTERNS:
        for m in pattern.finditer(js_text[:_MAX_JS]):
            snippet = js_text[max(0, m.start()-20):m.end()+40].replace("\n", " ")[:200]
            key = (pattern.pattern[:30], m.group(0)[:30])
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "severity": severity,
                "description": description,
                "snippet": snippet.strip(),
                "source": source_id,
            })
    return findings


class PostMessageSecurityScanner(BaseScanner):
    """Detects unsafe postMessage patterns via static JavaScript analysis."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "postMessage Security — target unreachable", "PASS",
                detail="No response; postMessage analysis skipped."))
            return self.results

        body = (resp.text or "")[:_MAX_BODY]
        all_findings: List[Dict] = []

        for m in _SCRIPT_RE.finditer(body):
            inline_js = m.group(1)
            if inline_js.strip():
                all_findings.extend(_scan_js(inline_js, "inline script"))

        scanned_ext = 0
        for m in _EXT_SCRIPT_RE.finditer(body):
            if scanned_ext >= 3:
                break
            src = m.group(1)
            if src.startswith("//"):
                src = "https:" + src
            if not src.startswith("http"):
                src = urljoin(url, src)
            if urlparse(src).netloc != urlparse(url).netloc:
                continue

            js_resp = self.http.get(src)
            if js_resp and js_resp.text:
                all_findings.extend(_scan_js(js_resp.text, src))
                scanned_ext += 1

        if not all_findings:
            log_pass(logger, f"postMessage Security — no unsafe postMessage patterns on {url}")
            self.results.append(self._result(
                url,
                "postMessage Security — no unsafe postMessage patterns detected",
                "PASS",
                detail=(
                    "Scanned inline scripts and up to 3 same-origin external JS files. "
                    "No wildcard origins, missing origin checks, or unsafe event.data usage found."
                ),
            ))
            return self.results

        seen_types: set = set()
        for f in all_findings[:20]:
            desc_key = f["description"][:50]
            if desc_key in seen_types:
                continue
            seen_types.add(desc_key)

            status = f["severity"]
            if status == "FAIL":
                log_fail(logger, f"postMessage Security — {f['description'][:60]}")
            else:
                log_warn(logger, f"postMessage Security — {f['description'][:60]}")

            self.results.append(self._result(
                url,
                f"postMessage Security — {f['description'][:100]}",
                status,
                detail=(
                    f"Source: {f['source']}\n\n"
                    f"{f['description']}\n\n"
                    f"Code snippet:\n  {f['snippet']}\n\n"
                    f"Always validate event.origin against an explicit allowlist before "
                    f"processing event.data. Use a specific target origin instead of '*' "
                    f"when calling postMessage()."
                ),
            ))

        return self.results
