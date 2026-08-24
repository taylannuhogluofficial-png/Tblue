"""Import Map security scanner — dependency confusion, module override, external specifiers."""
import re
from .base import BaseScanner

_IM_TAG_RE   = re.compile(r'<script[^>]+type\s*=\s*["\']importmap["\']', re.I | re.S)
_IM_ATTR_RE  = re.compile(r'"importmap"', re.I)
_IM_ANY_RE   = re.compile(r'(?:type\s*=\s*["\']importmap["\']|importMap)', re.I)

# External URL in import map (CDN dependency confusion)
_IM_EXTERNAL_RE = re.compile(
    r'"imports"\s*:\s*\{[^}]*"[^"]+"\s*:\s*"https?://(?!localhost|127\.0\.0\.1)[^"]+',
    re.I | re.S
)

# Remapping built-in modules (overriding node:* or bare specifiers to attacker URLs)
_IM_OVERRIDE_BUILTIN_RE = re.compile(
    r'"(?:lodash|react|vue|axios|jquery|moment)"\s*:\s*"https?://(?!(?:cdn\.|unpkg\.|jsdelivr\.|skypack\.))',
    re.I | re.S
)

# Import map from inline script with user-controlled content (DOM-based)
_IM_DYNAMIC_RE = re.compile(
    r'(?:innerHTML|insertAdjacentHTML|document\.write)[^;]{0,200}importmap', re.I | re.S
)

# Scopes pointing to external untrusted origins
_IM_SCOPES_EXTERNAL_RE = re.compile(
    r'"scopes"\s*:\s*\{[^}]*"https?://(?!localhost)', re.I | re.S
)

# Import map integrity missing (no integrity attribute on importmap script)
_IM_NO_INTEGRITY_RE = re.compile(r'type\s*=\s*["\']importmap["\'](?![^>]*integrity)', re.I | re.S)


class ImportMapSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "import_map_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _IM_ANY_RE.search(body):
            return [self._result(url, "import_map_not_used", "INFO",
                                 detail="Import Map not detected")]

        results = []

        if _IM_EXTERNAL_RE.search(body):
            results.append(self._result(url, "import_map_external_url", "WARN",
                                        detail="Import map specifier resolves to external URL — supply chain / CDN dependency confusion risk"))

        if _IM_OVERRIDE_BUILTIN_RE.search(body):
            results.append(self._result(url, "import_map_overrides_known_package", "FAIL",
                                        detail="Import map overrides well-known package to non-CDN URL — dependency hijacking"))

        if _IM_DYNAMIC_RE.search(body):
            results.append(self._result(url, "import_map_injected_dynamically", "FAIL",
                                        detail="Import map injected via innerHTML/document.write — attacker-controlled module resolution"))

        if _IM_SCOPES_EXTERNAL_RE.search(body):
            results.append(self._result(url, "import_map_external_scopes", "WARN",
                                        detail="Import map scopes redirect to external origins — module scope hijacking risk"))

        if _IM_NO_INTEGRITY_RE.search(body):
            results.append(self._result(url, "import_map_missing_integrity", "WARN",
                                        detail="Import map script lacks integrity attribute — map tampering undetected"))

        if not results:
            results.append(self._result(url, "import_map_found_no_issues", "PASS",
                                        detail="Import Map usage appears safe"))

        return results
