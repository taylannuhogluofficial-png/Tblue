"""
Import Map Security Scanner.

ES Module Import Maps (<script type="importmap">) redefine how module specifiers
resolve to URLs. Security issues:

1. External module without integrity:
   `{"imports": {"react": "https://cdn.example.com/react.js"}}` — CDN compromise
   replaces a core dependency for every ES module import on the page.
2. HTTP (non-TLS) module URL on HTTPS page:
   Cleartext module delivery is trivially MITMed and replaced with malicious code.
3. data: or javascript: module specifier:
   Allows code execution via import resolution — exotic CSP bypass vector.
4. Scope-based override for trusted modules:
   Import map scopes can remap third-party modules within specific path prefixes,
   creating hijack opportunities within sandboxed areas of the app.
5. Overly broad scope key ("/") remaps all relative imports globally.
6. Multiple import maps (only the first is used, others silently ignored — confusion).

CWE-829: Inclusion of Functionality from Untrusted Control Sphere
CWE-494: Download of Code Without Integrity Check
"""

import json
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_IMPORTMAP_RE = re.compile(
    r'<script\b[^>]*\btype\s*=\s*["\']importmap["\'][^>]*>(.*?)</script>',
    re.I | re.S,
)
_HTTP_SCHEME = re.compile(r'^http://', re.I)
_DATA_JS_RE  = re.compile(r'^(?:data:|javascript:)', re.I)
_HTTPS_EXT   = re.compile(r'^https://', re.I)


def _is_external(url: str) -> bool:
    try:
        p = urlparse(url)
        return bool(p.scheme and p.netloc)
    except Exception:
        return False


class ImportMapSecurityScanner(BaseScanner):
    """Detect security issues in ES module import maps."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "Import map security — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        body = resp.text or ""
        maps = _IMPORTMAP_RE.findall(body)

        if not maps:
            log_pass(logger, f"No import maps at {url}")
            self.results.append(self._result(
                url, "Import map security — no import maps found", "PASS",
                detail="No <script type=\"importmap\"> elements detected."
            ))
            return self.results

        if len(maps) > 1:
            log_warn(logger, f"Multiple import maps at {url} — only first is used")
            self.results.append(self._result(
                url,
                f"Import map security — {len(maps)} import maps present (only first honoured)",
                "WARN",
                detail=(
                    f"Found {len(maps)} <script type=\"importmap\"> elements. Browsers only "
                    "process the first import map; subsequent ones are silently ignored. "
                    "This creates confusion and may allow the ignored maps to be injected "
                    "by an attacker if they control later page content. "
                    "Fix: use exactly one import map per page."
                )
            ))
            findings += 1

        for map_json in maps:
            if findings >= 10:
                break
            try:
                data = json.loads(map_json.strip())
            except (json.JSONDecodeError, ValueError):
                log_warn(logger, f"Malformed import map JSON at {url}")
                self.results.append(self._result(
                    url, "Import map security — malformed import map JSON", "WARN",
                    detail=(
                        "The <script type=\"importmap\"> content is not valid JSON. "
                        "Browsers may reject or partially parse it. "
                        "Fix: validate import map JSON syntax."
                    )
                ))
                findings += 1
                continue

            imports = data.get("imports", {})
            scopes  = data.get("scopes", {})

            # Check each import specifier → URL mapping
            for specifier, module_url in imports.items():
                if not isinstance(module_url, str):
                    continue
                if _DATA_JS_RE.match(module_url):
                    log_fail(logger, f"Import map data:/javascript: specifier at {url}: {specifier}")
                    self.results.append(self._result(
                        url,
                        f"Import map security — data:/javascript: module URL for '{specifier}'",
                        "FAIL",
                        detail=(
                            f"Import map maps '{specifier}' to '{module_url[:80]}'. "
                            "data: and javascript: URLs as module specifiers execute "
                            "arbitrary code when the module is imported. This is a "
                            "CSP bypass vector. Fix: only allow https:// module URLs."
                        )
                    ))
                    findings += 1
                elif _HTTP_SCHEME.match(module_url):
                    log_fail(logger, f"Import map HTTP module URL at {url}: {specifier}")
                    self.results.append(self._result(
                        url,
                        f"Import map security — HTTP (non-TLS) module URL for '{specifier}'",
                        "FAIL",
                        detail=(
                            f"Import map maps '{specifier}' to '{module_url[:80]}' over HTTP. "
                            "Cleartext module delivery on an HTTPS page is a mixed content "
                            "violation and allows MITM injection of malicious code. "
                            "Fix: use https:// URLs in import maps."
                        )
                    ))
                    findings += 1
                elif _is_external(module_url) and _HTTPS_EXT.match(module_url):
                    log_warn(logger, f"Import map external module without integrity at {url}: {specifier}")
                    self.results.append(self._result(
                        url,
                        f"Import map security — external module URL without SRI for '{specifier}'",
                        "WARN",
                        detail=(
                            f"Import map maps '{specifier}' to external URL '{module_url[:80]}'. "
                            "If the CDN or host serving this module is compromised, all pages "
                            "importing this specifier will execute malicious code. "
                            "Fix: import maps do not support integrity attributes — host "
                            "modules on your own origin or use a trusted CDN with CSP "
                            "script-src hashes to restrict allowed module content."
                        )
                    ))
                    findings += 1

                if findings >= 10:
                    break

            # Check scopes for overly broad or dangerous remapping
            for scope_path, scope_imports in scopes.items():
                if not isinstance(scope_imports, dict):
                    continue
                if scope_path == "/":
                    log_warn(logger, f"Import map global scope override at {url}")
                    self.results.append(self._result(
                        url,
                        "Import map security — global scope '/' overrides all imports",
                        "WARN",
                        detail=(
                            "An import map scope with key '/' remaps modules for all paths "
                            "on the origin. This global override can mask intended import "
                            "resolution and is a high-impact misconfiguration if the scope "
                            "content is attacker-influenced. "
                            "Fix: use specific scope paths rather than the catch-all '/'."
                        )
                    ))
                    findings += 1
                    break

        if not self.results:
            log_pass(logger, f"Import maps appear safe at {url}")
            self.results.append(self._result(
                url, "Import map security — import map uses safe module URLs", "PASS",
                detail="Import map found; all module URLs use HTTPS without dangerous specifiers."
            ))

        return self.results
