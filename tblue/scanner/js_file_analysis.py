"""
External JavaScript File — DOM Sink & Security Pattern Analysis.

Fetches all same-origin <script src="..."> files linked from the target page
and performs static analysis for dangerous JavaScript patterns:

  1. DOM XSS sinks — innerHTML, document.write, eval, new Function, etc.
  2. Source-near-sink detection — user-controlled sources (location.hash,
     URLSearchParams, document.referrer) adjacent to dangerous sinks
  3. Prototype pollution — .__proto__, constructor.prototype assignments
  4. Unsafe postMessage handler — addEventListener("message") without origin
  5. document.domain relaxation — loosens same-origin policy
  6. dangerouslySetInnerHTML (React), v-html (Vue), ng-bind-html (Angular)
  7. Insecure credential fetch — fetch() with credentials to cross-origin URL

This is static analysis only — no code execution, no payloads sent.
Complements dom.py (inline JS) and js_secrets.py (credentials in JS).

CWE-79:  Cross-Site Scripting
CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes
OWASP A03:2021 — Injection
"""

import re
from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

_MAX_JS_FILES  = 25
_MAX_JS_BYTES  = 512_000  # 500 KB per file

# ── DOM XSS sink patterns ─────────────────────────────────────────────────────

# (label, regex, severity)
_SINKS: List[Tuple[str, re.Pattern, str]] = [
    # Direct eval / code execution — highest risk
    ("eval() call",
     re.compile(r"\beval\s*\(", re.I),
     "FAIL"),
    ("new Function() call",
     re.compile(r"\bnew\s+Function\s*\(", re.I),
     "FAIL"),
    ("setTimeout / setInterval with string arg",
     re.compile(r"\b(?:setTimeout|setInterval)\s*\(\s*['\"`]", re.I),
     "FAIL"),

    # DOM mutation — very common XSS vector
    ("innerHTML / outerHTML assignment",
     re.compile(r"\b(?:inner|outer)HTML\s*(?:\+?=|setAttribute\s*\(['\"](?:inner|outer)html)", re.I),
     "WARN"),
    ("document.write / writeln",
     re.compile(r"\bdocument\.write(?:ln)?\s*\(", re.I),
     "WARN"),
    ("insertAdjacentHTML",
     re.compile(r"\binsertAdjacentHTML\s*\(", re.I),
     "WARN"),

    # Framework-specific unsafe patterns
    ("React dangerouslySetInnerHTML",
     re.compile(r"\bdangerouslySetInnerHTML\s*=", re.I),
     "WARN"),
    ("Vue v-html directive",
     re.compile(r"\bv-html\s*=", re.I),
     "WARN"),
    ("Angular ng-bind-html / bypassSecurityTrustHtml",
     re.compile(r"\bng-bind-html\b|\bbypassSecurityTrustHtml\s*\(", re.I),
     "WARN"),

    # Redirect sink
    ("Unvalidated URL assignment to location",
     re.compile(r"\b(?:window\.location|location\.href|location\.replace|location\.assign)\s*=\s*(?!['\"]https?://[a-zA-Z]|['\"]/)", re.I),
     "WARN"),
]

# ── Prototype pollution patterns ───────────────────────────────────────────────

_PROTO_POLLUTION = re.compile(
    r'\[[\'""]__proto__[\'""\]]\s*\]|'
    r'\.__proto__\s*(?:\[|\.)|'
    r'constructor\.prototype\s*\[',
    re.I,
)

# ── postMessage without origin check ─────────────────────────────────────────

_POSTMSG_LISTENER = re.compile(
    r'addEventListener\s*\(\s*["\']message["\']',
    re.I,
)
_ORIGIN_GUARD = re.compile(
    r'\bevent\.origin\b|\bmessage\.origin\b|\boriginAllowed\b|\btrustedOrigins?\b',
    re.I,
)

# ── document.domain relaxation ────────────────────────────────────────────────

_DOC_DOMAIN = re.compile(r'\bdocument\.domain\s*=', re.I)

# ── User-controlled source patterns (for source-near-sink scoring) ────────────

_SOURCES = re.compile(
    r'location\.(?:search|hash|href|pathname|query)|'
    r'URLSearchParams|'
    r'document\.referrer|'
    r'window\.name\b|'
    r'decodeURIComponent|'
    r'getParameter|'
    r'localStorage\.getItem|'
    r'sessionStorage\.getItem',
    re.I,
)

# ── Unsafe credential fetch ───────────────────────────────────────────────────

_CRED_FETCH = re.compile(
    r'fetch\s*\([^)]{0,300}credentials\s*:\s*["\']include["\']',
    re.I | re.S,
)
_CROSS_ORIGIN_URL = re.compile(
    r'fetch\s*\(\s*["\']https?://(?!(?:localhost|127\.0\.0\.1))',
    re.I,
)


class JSFileAnalysisScanner(BaseScanner):
    """Fetch and statically analyse external JS files for DOM XSS sinks."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results: List[Dict[str, Any]] = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "JS file analysis — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        js_urls = _extract_same_origin_js(url, resp.text)
        if not js_urls:
            self.results.append(self._result(
                url, "JS file analysis — no same-origin JS files found", "PASS",
                detail=(
                    "No same-origin JavaScript files found linked from this page. "
                    "If external CDN scripts are used, review them separately."
                )
            ))
            return self.results

        for js_url in js_urls[:_MAX_JS_FILES]:
            self._analyse_js_file(js_url)

        if not any(r["status"] in ("FAIL", "WARN") for r in self.results):
            log_pass(logger, f"JS file analysis — no dangerous patterns in {len(js_urls)} file(s)")
            self.results.append(self._result(
                url,
                "JS file analysis — no dangerous DOM sink patterns found",
                "PASS",
                detail=(
                    f"Analysed {min(len(js_urls), _MAX_JS_FILES)} same-origin JavaScript file(s): "
                    "no dangerous DOM sinks, prototype pollution, unsafe postMessage handlers, "
                    "or document.domain relaxation detected. "
                    "CWE-79."
                )
            ))

        return self.results

    def _analyse_js_file(self, js_url: str) -> None:
        resp = self.http.get(js_url)
        if resp is None or resp.status_code != 200:
            return

        content = resp.text or ""
        if not content.strip():
            return

        # Truncate oversized files
        content = content[:_MAX_JS_BYTES]

        self._check_dom_sinks(js_url, content)
        self._check_proto_pollution(js_url, content)
        self._check_postmessage(js_url, content)
        self._check_doc_domain(js_url, content)
        self._check_cred_fetch(js_url, content)

    def _check_dom_sinks(self, js_url: str, content: str) -> None:
        has_source = bool(_SOURCES.search(content))

        for label, pattern, base_severity in _SINKS:
            m = pattern.search(content)
            if not m:
                continue

            # Upgrade severity if a user-controlled source is also in the file
            if has_source and base_severity == "WARN":
                severity = "FAIL"
                source_note = (
                    " User-controlled data sources (location.hash, URLSearchParams, "
                    "document.referrer, localStorage) are also present in this file, "
                    "increasing the risk of a real XSS sink."
                )
            else:
                severity = base_severity
                source_note = ""

            if severity == "FAIL":
                log_fail(logger, f"JS DOM sink '{label}' in {js_url}")
            else:
                log_warn(logger, f"JS DOM sink '{label}' in {js_url}")

            self.results.append(self._result(
                js_url,
                f"JS file analysis — DOM sink: {label}",
                severity,
                detail=(
                    f"'{label}' detected in {js_url}. "
                    f"If attacker-controlled data reaches this sink, XSS is possible.{source_note} "
                    "Fix: sanitise all dynamic HTML with DOMPurify, use textContent instead of "
                    "innerHTML, and avoid eval(). Review data flows into this sink. "
                    "CWE-79, OWASP A03."
                )
            ))
            return  # one finding per file per category to avoid noise

    def _check_proto_pollution(self, js_url: str, content: str) -> None:
        if _PROTO_POLLUTION.search(content):
            log_warn(logger, f"Prototype pollution pattern in {js_url}")
            self.results.append(self._result(
                js_url,
                "JS file analysis — prototype pollution pattern",
                "WARN",
                detail=(
                    f"A prototype pollution pattern (__proto__ or constructor.prototype "
                    f"mutation) was detected in {js_url}. "
                    "If user input can reach these assignments, an attacker can modify "
                    "built-in object prototypes, leading to logic bypass or code execution. "
                    "Fix: use Object.create(null) for data maps, validate JSON with JSON schema, "
                    "freeze sensitive prototypes. CWE-915."
                )
            ))

    def _check_postmessage(self, js_url: str, content: str) -> None:
        if _POSTMSG_LISTENER.search(content) and not _ORIGIN_GUARD.search(content):
            log_warn(logger, f"postMessage listener without origin check in {js_url}")
            self.results.append(self._result(
                js_url,
                "JS file analysis — postMessage listener without origin validation",
                "WARN",
                detail=(
                    f"A postMessage event listener in {js_url} does not check event.origin. "
                    "Any cross-origin page can send messages that this handler will process, "
                    "enabling data theft or action hijacking. "
                    "Fix: always validate event.origin against an explicit allowlist before "
                    "processing postMessage data. CWE-346."
                )
            ))

    def _check_doc_domain(self, js_url: str, content: str) -> None:
        if _DOC_DOMAIN.search(content):
            log_warn(logger, f"document.domain relaxation in {js_url}")
            self.results.append(self._result(
                js_url,
                "JS file analysis — document.domain relaxation",
                "WARN",
                detail=(
                    f"document.domain is assigned in {js_url}, which relaxes the same-origin "
                    "policy and allows framing attacks between subdomains. "
                    "Fix: use postMessage with strict origin checks for cross-subdomain "
                    "communication instead of document.domain. CWE-183."
                )
            ))

    def _check_cred_fetch(self, js_url: str, content: str) -> None:
        if _CRED_FETCH.search(content) and _CROSS_ORIGIN_URL.search(content):
            log_warn(logger, f"fetch with credentials to cross-origin URL in {js_url}")
            self.results.append(self._result(
                js_url,
                "JS file analysis — fetch with credentials to cross-origin URL",
                "WARN",
                detail=(
                    f"A fetch() call with credentials:'include' to an external (cross-origin) URL "
                    f"was detected in {js_url}. "
                    "If the target server allows the current origin in CORS, cookies and auth "
                    "tokens are sent cross-origin. Verify the server's CORS policy is restrictive. "
                    "CWE-346, OWASP A05."
                )
            ))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_same_origin_js(page_url: str, html: str) -> List[str]:
    """Return same-origin JS URLs linked from the page."""
    try:
        soup   = BeautifulSoup(html, "html.parser")
        domain = urlparse(page_url).netloc
        urls: List[str] = []
        seen: set = set()

        for tag in soup.find_all("script", src=True):
            src = tag.get("src", "").strip()
            if not src:
                continue
            full = urljoin(page_url, src)
            parsed = urlparse(full)
            if parsed.netloc != domain:
                continue  # skip CDN / cross-origin scripts
            if not parsed.path.lower().endswith(".js") and "js" not in parsed.path.lower():
                continue
            clean = parsed._replace(fragment="", query="").geturl()
            if clean not in seen:
                seen.add(clean)
                urls.append(clean)

        return urls
    except Exception:
        return []
