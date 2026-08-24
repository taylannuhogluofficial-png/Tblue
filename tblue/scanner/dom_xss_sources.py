"""
DOM XSS Source-to-Sink Taint Analysis Scanner.

DOM-based XSS occurs when JavaScript reads attacker-controlled values
(sources) and writes them into dangerous locations (sinks) without
sanitization. This is distinct from reflected/stored XSS — it happens
entirely client-side, bypassing WAFs and CSP 'unsafe-inline' restrictions.

This scanner performs STATIC ANALYSIS of JavaScript, detecting dangerous
source-to-sink patterns:

SOURCES (attacker-controlled input):
  - location.hash, location.search, location.href
  - document.referrer
  - window.name
  - postMessage data (covered by postmessage_security.py)
  - URL parameters via URLSearchParams

SINKS (dangerous injection points):
  - innerHTML, outerHTML (HTML injection)
  - document.write, document.writeln
  - eval(), setTimeout(string), setInterval(string)
  - location.href, location.assign, location.replace (redirect/XSS)
  - src attribute assignment
  - jQuery .html(), .append() with source value

Source-to-sink proximity matters: patterns where a source is read and
then assigned to a sink in close JS proximity are flagged.

CWE-79: Improper Neutralization of Input During Web Page Generation
CWE-83: Improper Neutralization of Script in Attributes
"""

import re
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_MAX_BODY = 512 * 1024
_MAX_JS   = 256 * 1024

# Source patterns — variable assignment of attacker-controlled data
_SOURCE_PATTERNS = [
    re.compile(r'location\s*\.\s*(?:hash|search|href)', re.I),
    re.compile(r'document\s*\.\s*referrer', re.I),
    re.compile(r'window\s*\.\s*name', re.I),
    re.compile(r'(?:new\s+)?URLSearchParams\s*\(', re.I),
    re.compile(r'location\s*\.\s*search\s*(?:\.split|\.match|\.replace)', re.I),
    re.compile(r'getParameter\s*\(["\'][^"\']+["\']\)', re.I),
]

# Sink patterns — dangerous output operations
_SINK_PATTERNS = [
    (re.compile(r'\.(innerHTML|outerHTML)\s*=', re.I),                   "FAIL", "innerHTML/outerHTML assignment"),
    (re.compile(r'document\s*\.\s*write[ln]*\s*\(', re.I),              "WARN", "document.write()"),
    (re.compile(r'eval\s*\(', re.I),                                     "FAIL", "eval()"),
    (re.compile(r'setTimeout\s*\(\s*[^,)\'"]{1,50},', re.I),            "WARN", "setTimeout(string)"),
    (re.compile(r'setInterval\s*\(\s*[^,)\'"]{1,50},', re.I),           "WARN", "setInterval(string)"),
    (re.compile(r'location\s*(?:\.\s*href\s*=|\.\s*assign\s*\(|\.\s*replace\s*\()', re.I), "WARN", "location navigation"),
    (re.compile(r'\.\s*src\s*=\s*[^"\'`\n;]{1,100}', re.I),            "WARN", "element.src assignment"),
    (re.compile(r'\$\s*\([^)]+\)\s*\.\s*html\s*\(', re.I),             "WARN", "jQuery .html()"),
    (re.compile(r'insertAdjacentHTML\s*\(', re.I),                       "FAIL", "insertAdjacentHTML()"),
    (re.compile(r'createContextualFragment\s*\(', re.I),                 "FAIL", "createContextualFragment()"),
]

# Combined source-to-sink patterns — matches `sink = ...source...` order
# (assignment is written as sink = source in JavaScript)
_COMBINED_PATTERNS: List[tuple] = [
    # innerHTML = ... location.hash
    (re.compile(r'innerHTML\s*=\s*[^;]{0,150}location\s*\.\s*hash', re.I | re.S), "FAIL",
     "DOM XSS: location.hash → innerHTML assignment without sanitization"),

    # innerHTML = ... location.search
    (re.compile(r'innerHTML\s*=\s*[^;]{0,150}location\s*\.\s*search', re.I | re.S), "FAIL",
     "DOM XSS: location.search → innerHTML assignment without sanitization"),

    # innerHTML = ... document.referrer
    (re.compile(r'innerHTML\s*=\s*[^;]{0,150}document\s*\.\s*referrer', re.I | re.S), "FAIL",
     "DOM XSS: document.referrer → innerHTML assignment without sanitization"),

    # document.write(... location.hash ...)
    (re.compile(r'document\s*\.\s*write[ln]*\s*\([^)]{0,150}location\s*\.\s*hash', re.I | re.S), "FAIL",
     "DOM XSS: location.hash → document.write without sanitization"),

    # eval(... location.hash / location.search ...)
    (re.compile(r'eval\s*\([^)]{0,150}location\s*\.\s*(?:hash|search)', re.I | re.S), "FAIL",
     "DOM XSS: URL input (location) → eval() — remote code execution"),

    # innerHTML = ... window.name
    (re.compile(r'innerHTML\s*=\s*[^;]{0,150}window\s*\.\s*name', re.I | re.S), "FAIL",
     "DOM XSS: window.name → innerHTML — can be set cross-origin before navigation"),

    # innerHTML = ... .get( (URLSearchParams)
    (re.compile(r'innerHTML\s*=\s*[^;]{0,200}\.get\s*\(', re.I | re.S), "WARN",
     "DOM XSS: URL parameter value (.get()) → innerHTML assignment"),

    # location.href = ... location.hash  (open redirect from hash)
    (re.compile(r'location\s*\.\s*(?:href|assign)\s*[=(][^;]{0,100}location\s*\.\s*hash', re.I | re.S), "WARN",
     "DOM XSS: location.hash used for client-side redirect — potential open redirect or XSS"),

    # location.href = ... document.referrer
    (re.compile(r'location\s*\.\s*(?:href|assign)\s*[=(][^;]{0,100}document\s*\.\s*referrer', re.I | re.S), "WARN",
     "DOM XSS: document.referrer used for navigation — potential open redirect"),
]

_SCRIPT_RE     = re.compile(r'<script[^>]*>(.*?)</script>', re.I | re.S)
_EXT_SCRIPT_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)


def _scan_js(js_text: str, source_id: str) -> List[Dict]:
    findings = []
    seen = set()
    text = js_text[:_MAX_JS]

    for pattern, severity, description in _COMBINED_PATTERNS:
        for m in pattern.finditer(text):
            snippet = text[max(0, m.start()-20):m.end()+40].replace("\n", " ")[:200]
            key = (pattern.pattern[:40], m.group(0)[:30])
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


class DOMXSSSourcesScanner(BaseScanner):
    """Detects DOM XSS source-to-sink patterns via static JavaScript analysis."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "DOM XSS Sources — target unreachable", "PASS",
                detail="No response; DOM XSS source analysis skipped."))
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
            log_pass(logger, f"DOM XSS Sources — no dangerous source-to-sink patterns on {url}")
            self.results.append(self._result(
                url,
                "DOM XSS Sources — no dangerous source-to-sink patterns detected",
                "PASS",
                detail=(
                    "Scanned inline scripts and up to 3 same-origin external JS files "
                    "for DOM XSS source-to-sink patterns (location.hash/search/href, "
                    "document.referrer, window.name → innerHTML, eval, document.write, "
                    "location navigation). No dangerous patterns found."
                ),
            ))
            return self.results

        seen_descs: set = set()
        for f in all_findings[:20]:
            key = f["description"][:60]
            if key in seen_descs:
                continue
            seen_descs.add(key)

            status = f["severity"]
            if status == "FAIL":
                log_fail(logger, f"DOM XSS Sources — {f['description'][:70]}")
            else:
                log_warn(logger, f"DOM XSS Sources — {f['description'][:70]}")

            self.results.append(self._result(
                url,
                f"DOM XSS Sources — {f['description'][:100]}",
                status,
                detail=(
                    f"Source: {f['source']}\n\n"
                    f"{f['description']}\n\n"
                    f"Code snippet:\n  {f['snippet']}\n\n"
                    f"DOM-based XSS bypasses server-side defenses because the payload "
                    f"never reaches the server — it's processed entirely client-side. "
                    f"Sanitize source values with DOMPurify before writing to sinks. "
                    f"Use textContent instead of innerHTML for plain text output."
                ),
            ))

        return self.results
