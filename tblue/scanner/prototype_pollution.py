"""
Prototype Pollution Scanner.

Fetches linked JavaScript bundles and scans for patterns associated with
prototype pollution vulnerabilities — both direct assignment to Object.prototype
and unsafe merge/extend/clone patterns that accept attacker-controlled keys.

Prototype pollution lets an attacker set properties on Object.prototype,
affecting every object in the application. This can escalate to RCE in
server-side Node.js contexts, and to XSS/DOM manipulation in browsers.

Checks:
  1. Direct __proto__ / constructor.prototype assignments
  2. Recursive merge/extend functions that don't sanitise keys
  3. Known vulnerable library patterns (jQuery < 3.4.0 $.extend, Lodash < 4.17.11)
  4. eval()/Function() combined with user-controlled data (escalation path)

All checks are static analysis of fetched JavaScript — no execution.

Paid equivalents: Burp Suite DOM Invader, PortSwigger Prototype Pollution labs.
"""

import re
from typing import Any, Dict, List, Set
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# ── Prototype pollution patterns ──────────────────────────────────────────────

# Direct assignment to prototype chain
_DIRECT_PROTO_RE = re.compile(
    r"""
    __proto__\s*[=\[]             # __proto__ = or __proto__[
    | constructor\s*\.\s*prototype\s*[=\[]   # constructor.prototype[
    | Object\s*\.\s*prototype\s*\[           # Object.prototype[
    | \.prototype\s*\.\s*\w+\s*=\s*function  # .prototype.method = function (common but context-dependent)
    """,
    re.I | re.VERBOSE,
)

# Unsafe recursive merge/extend signatures (no __proto__/constructor key check)
_UNSAFE_MERGE_RE = re.compile(
    r"""
    function\s+(?:merge|extend|assign|deepMerge|deepClone|deepCopy|clone|defaults)\s*\(
    | (?:merge|extend|deepMerge|deepExtend|defaults)\s*:\s*function
    | Object\.assign\s*\(                     # Object.assign without guard
    """,
    re.I | re.VERBOSE,
)

# Known vulnerable library patterns
_VULNERABLE_LIB_RE = re.compile(
    r"""
    jquery[/\-](?:[12]\.\d+\.\d+|3\.[0-3]\.\d+)   # jQuery < 3.4.0
    | lodash[/\-](?:0\.|1\.|2\.|3\.|4\.(?:[0-9]|1[0-6])\.)  # Lodash < 4.17.11
    | hoek[/\-](?:[0-5]\.)                          # Hoek < 6 (hapi ecosystem)
    | mootools[/\-]                                  # MooTools (all versions)
    | node-forge/(?:0\.[0-9]\.|1\.0\.)              # node-forge < 1.3.0
    """,
    re.I | re.VERBOSE,
)

# Merge patterns that DON'T check for prototype keys — the classic vuln pattern
_UNCHECKED_KEY_RE = re.compile(
    r"""
    for\s*\(\s*(?:var|let|const)?\s*\w+\s+in\s+\w+\s*\)   # for..in loop
    """,
    re.I | re.VERBOSE,
)

# Eval + string concat (escalation)
_EVAL_CONCAT_RE = re.compile(
    r"eval\s*\(\s*\w+\s*\+|Function\s*\(\s*\w+\s*\+",
    re.I,
)

# Patterns that indicate existing prototype-pollution guards (file likely already protected)
_SAFE_GUARD_RE = re.compile(
    r"""
    hasOwnProperty                                  # explicit hasOwnProperty check
    | Object\.create\s*\(\s*null\s*\)              # Object.create(null) — null prototype
    | Object\.getOwnPropertyDescriptor             # descriptor-level safety check
    | [=!]==\s*['"]__proto__['"]                   # if (key === '__proto__') guard
    | ['"]__proto__['"]\s*[=!]==                   # reversed comparison
    """,
    re.I | re.VERBOSE,
)

_MAX_JS_SIZE = 2 * 1024 * 1024  # 2 MB — skip very large bundles


class PrototypePollutionScanner(BaseScanner):
    """Static analysis of JS bundles for prototype pollution vulnerabilities."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        resp = self.http.get(url)
        if not resp:
            return self.results

        body = resp.text or ""
        soup = BeautifulSoup(body, "html.parser")

        js_urls: List[str] = []
        for script in soup.find_all("script"):
            src = script.attrs.get("src", "")
            if src:
                js_urls.append(src if src.startswith("http") else urljoin(url, src))

        if not js_urls:
            log_pass(logger, f"No external JS files found on {url}")
            self.results.append(self._result(
                url, "Prototype pollution — no external JS to scan", "PASS",
                detail="No external JavaScript files found on this page."
            ))
            return self.results

        direct_findings: List[str]     = []
        unsafe_merge_files: List[str]  = []
        vulnerable_libs: List[str]     = []
        eval_concat_files: List[str]   = []
        scanned = 0

        for js_url in js_urls[:20]:  # cap at 20 JS files
            try:
                js_resp = self.http.get(js_url)
                if not js_resp or js_resp.status_code != 200:
                    continue
                js_body = js_resp.text or ""
                if len(js_body) > _MAX_JS_SIZE:
                    continue
                scanned += 1

                has_safe_guard = bool(_SAFE_GUARD_RE.search(js_body))

                # Direct prototype assignments
                if _DIRECT_PROTO_RE.search(js_body) and not has_safe_guard:
                    direct_findings.append(js_url)

                # Vulnerable library version strings
                if _VULNERABLE_LIB_RE.search(js_url) or _VULNERABLE_LIB_RE.search(js_body[:500]):
                    vulnerable_libs.append(js_url)

                # Unsafe merge/extend without guard
                if _UNSAFE_MERGE_RE.search(js_body) and _UNCHECKED_KEY_RE.search(js_body):
                    if not has_safe_guard:
                        unsafe_merge_files.append(js_url)

                # eval + string concat
                if _EVAL_CONCAT_RE.search(js_body):
                    eval_concat_files.append(js_url)

            except Exception:
                continue

        # ── Emit findings ──────────────────────────────────────────────────
        if direct_findings:
            examples = ", ".join(direct_findings[:3])
            log_fail(logger, f"Direct __proto__ / prototype assignment: {examples}")
            self.results.append(self._result(
                url, "Prototype pollution — direct __proto__ assignment in JS", "FAIL",
                detail=(
                    f"JavaScript file(s) contain direct assignments to __proto__ or "
                    f"Object.prototype without observable prototype key sanitisation: {examples}. "
                    "Prototype pollution enables attackers to inject properties into "
                    "Object.prototype, affecting all objects in the application and "
                    "potentially enabling XSS or property override attacks. "
                    "Fix: audit recursive merge/extend functions to reject __proto__, "
                    "constructor, and prototype as keys; prefer Object.create(null) "
                    "for config objects; use structured clone instead of manual deep copy."
                )
            ))

        if vulnerable_libs:
            examples = ", ".join(vulnerable_libs[:3])
            log_fail(logger, f"Vulnerable library versions with known PP CVEs: {examples}")
            self.results.append(self._result(
                url, "Prototype pollution — vulnerable library version detected", "FAIL",
                detail=(
                    f"Library file(s) match known prototype pollution CVE version ranges: {examples}. "
                    "Known CVEs: jQuery < 3.4.0 (CVE-2019-11358, $.extend deep merge), "
                    "Lodash < 4.17.11 (CVE-2018-3721, _.merge / _.defaultsDeep), "
                    "Hoek < 6.0.0 (CVE-2018-3728). "
                    "Fix: upgrade to patched versions; review changelog for prototype "
                    "pollution fixes; run npm audit / yarn audit regularly."
                )
            ))

        if unsafe_merge_files and not direct_findings:
            examples = ", ".join(unsafe_merge_files[:3])
            log_warn(logger, f"Unsafe merge/extend pattern without guard: {examples}")
            self.results.append(self._result(
                url, "Prototype pollution — unsafe merge pattern without key guard", "WARN",
                detail=(
                    f"JavaScript file(s) contain merge/extend/clone functions with for..in "
                    f"loops but no observable guard against __proto__ or constructor keys: {examples}. "
                    "These patterns are potential prototype pollution sinks. "
                    "Fix: add key guards — `if (key === '__proto__' || key === 'constructor' || "
                    "key === 'prototype') continue;` — before assigning in merge loops."
                )
            ))

        if eval_concat_files:
            examples = ", ".join(eval_concat_files[:3])
            log_warn(logger, f"eval() with string concatenation: {examples}")
            self.results.append(self._result(
                url, "Prototype pollution — eval() with string concatenation (escalation path)", "WARN",
                detail=(
                    f"JavaScript file(s) use eval() or Function() with string concatenation: {examples}. "
                    "If combined with prototype pollution, this pattern can escalate "
                    "prototype pollution to arbitrary code execution (Property Injection → RCE). "
                    "Fix: eliminate eval() from application code; if truly necessary, "
                    "never pass user-controlled data to eval()."
                )
            ))

        if not self.results:
            log_pass(logger, f"No prototype pollution indicators in {scanned} JS file(s) on {url}")
            self.results.append(self._result(
                url, "Prototype pollution — no indicators found", "PASS",
                detail=(
                    f"Scanned {scanned} JavaScript file(s): no direct prototype assignments, "
                    "unsafe merge patterns, or known vulnerable library versions detected."
                )
            ))

        return self.results
