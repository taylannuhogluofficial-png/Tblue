"""Import Assertions / Module Attributes security scanner — passive detection of module import misuse."""
import re
from .base import BaseScanner

_IA_ANY_RE = re.compile(
    r'(?:assert\s*\{\s*type\s*:|with\s*\{\s*type\s*:|import\s*\([^)]+\)\s*(?:assert|with)\s*\{|'
    r'importmap\b|<script[^>]+type\s*=\s*["\']importmap["\'])',
    re.I,
)

_IA_URL_FROM_PARAM_RE = re.compile(
    r'import\s*\([^)]*(?:searchParams|location\.hash|location\.href|decodeURIComponent)[^)]*\)'
    r'[^;]{0,100}(?:assert|with)\s*\{',
    re.I,
)

_IA_IMPORTMAP_INJECT_RE = re.compile(
    r'(?:innerHTML|document\.write|insertAdjacentHTML)[^;]{0,200}importmap',
    re.I,
)

_IA_JSON_MODULE_SENSITIVE_RE = re.compile(
    r'import\s*\([^)]*(?:cookie|token|auth|password|secret)[^)]*\)\s*(?:assert|with)\s*\{\s*type\s*:\s*["\']json["\']',
    re.I,
)

_IA_IMPORTMAP_EXTERNAL_RE = re.compile(
    r'["\']importmap["\'][^;]{0,300}["\']https?://(?!(?:localhost|127\.0\.0\.1))',
    re.I,
)


class ImportAssertionsSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "import_assertions_not_used", "PASS")]

        body = resp.text

        if not _IA_ANY_RE.search(body):
            return [self._result(url, "import_assertions_not_used", "PASS")]

        findings = []

        if _IA_URL_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "import_assertions_url_from_param", "FAIL",
                detail="Dynamic import() URL from URL parameter with type assertion — attacker-controlled module loading.",
            ))

        if _IA_IMPORTMAP_INJECT_RE.search(body):
            findings.append(self._result(
                url, "importmap_injected_via_dom", "FAIL",
                detail="Import map injected via innerHTML/document.write — dynamic module specifier hijacking.",
            ))

        if _IA_JSON_MODULE_SENSITIVE_RE.search(body):
            findings.append(self._result(
                url, "import_json_module_sensitive_path", "WARN",
                detail="JSON module imported from path containing token/cookie/auth keywords — sensitive data imported as module.",
            ))

        if _IA_IMPORTMAP_EXTERNAL_RE.search(body):
            findings.append(self._result(
                url, "importmap_external_specifier", "WARN",
                detail="Import map maps module specifier to external URL — third-party module substitution attack vector.",
            ))

        return findings or [self._result(url, "import_assertions_safe", "PASS")]
