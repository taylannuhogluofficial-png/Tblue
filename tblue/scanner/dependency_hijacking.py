"""Dependency Hijacking scanner — detection of package name confusion, subdomain takeover via CDN, typosquatting."""
import re
from .base import BaseScanner

_DH_ANY_RE = re.compile(
    r'(?:require\s*\(|import\s*\(|import\s+["\']|from\s+["\']|'
    r'<script\s+src=["\']|unpkg\.com|cdn\.jsdelivr\.net|'
    r'npmjs\.com|jsdelivr\.net)',
    re.I,
)

_DH_EXTERNAL_SCRIPT_NO_SRI_RE = re.compile(
    r'<script\b[^>]+src\s*=\s*["\']https?://(?!(?:www\.)?(?:your-domain|localhost))[^"\']+["\']'
    r'(?![\s\S]{0,300}integrity\s*=)',
    re.I,
)

_DH_CDN_PACKAGE_FROM_PARAM_RE = re.compile(
    r'(?:unpkg\.com|cdn\.jsdelivr\.net|cdnjs\.com)[^"\']{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_DH_DYNAMIC_REQUIRE_FROM_PARAM_RE = re.compile(
    r'require\s*\([^)]{0,200}'
    r'(?:searchParams|location\.hash|userInput)',
    re.I,
)

_DH_DYNAMIC_IMPORT_FROM_PARAM_RE = re.compile(
    r'import\s*\([^)]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class DependencyHijackingScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "dependency_hijacking_not_used", "PASS")]

        body = resp.text
        if not _DH_ANY_RE.search(body):
            return [self._result(url, "dependency_hijacking_not_used", "PASS")]

        findings = []

        if _DH_EXTERNAL_SCRIPT_NO_SRI_RE.search(body):
            findings.append(self._result(
                url, "dependency_hijacking_no_sri", "WARN",
                detail="External <script src> from CDN without integrity= attribute — if CDN is compromised or hijacked, malicious script runs with full page privileges; SRI prevents this.",
            ))

        if _DH_CDN_PACKAGE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "dependency_hijacking_cdn_from_param", "FAIL",
                detail="CDN package URL built from URL parameter — attacker controls which package/version is loaded from unpkg/jsdelivr; classic dependency confusion attack.",
            ))

        if _DH_DYNAMIC_REQUIRE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "dependency_hijacking_require_from_param", "FAIL",
                detail="require() path from URL parameter/userInput — attacker-controlled module path enables loading of malicious local or network modules.",
            ))

        if _DH_DYNAMIC_IMPORT_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "dependency_hijacking_dynamic_import", "FAIL",
                detail="Dynamic import() with URL parameter — attacker controls which module is loaded; combined with open redirects enables loading remote malicious modules.",
            ))

        return findings or [self._result(url, "dependency_hijacking_safe", "PASS")]
