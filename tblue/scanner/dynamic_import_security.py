"""Dynamic import() security scanner — passive detection of script injection via import."""
import re
from .base import BaseScanner

_DI_ANY_RE = re.compile(
    r'(?:import\s*\([^)]+\)|import\.meta\b|importShim\s*\(|importmap\b)',
    re.I,
)

_DI_URL_FROM_PARAM_RE = re.compile(
    r'import\s*\([^)]*(?:searchParams|location\.hash|location\.href|decodeURIComponent)[^)]*\)',
    re.I,
)

_DI_EXTERNAL_DYNAMIC_RE = re.compile(
    r'import\s*\(\s*(?:[\'""]https?://(?!localhost|127\.0\.0\.1))',
    re.I,
)

_DI_CONCAT_URL_RE = re.compile(
    r'import\s*\(\s*(?:[`\'"][^`\'"]+[`\'"]\s*\+|\s*\`[^`]*\$\{)',
    re.I,
)

_DI_META_EXFIL_RE = re.compile(
    r'import\.meta\.[a-z]+[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class DynamicImportSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "dynamic_import_not_used", "PASS")]

        body = resp.text

        if not _DI_ANY_RE.search(body):
            return [self._result(url, "dynamic_import_not_used", "PASS")]

        findings = []

        if _DI_URL_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "dynamic_import_url_from_param", "FAIL",
                detail="import() specifier sourced from URL parameter — attacker-controlled script injection via dynamic import.",
            ))

        if _DI_EXTERNAL_DYNAMIC_RE.search(body):
            findings.append(self._result(
                url, "dynamic_import_external_script", "WARN",
                detail="import() loads script from external URL — unverified third-party code execution risk.",
            ))

        if _DI_CONCAT_URL_RE.search(body):
            findings.append(self._result(
                url, "dynamic_import_concatenated_url", "WARN",
                detail="import() URL built via string concatenation or template literal — potential import injection.",
            ))

        if _DI_META_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "dynamic_import_meta_exfil", "WARN",
                detail="import.meta data transmitted to remote endpoint — module metadata exfiltration.",
            ))

        return findings or [self._result(url, "dynamic_import_safe", "PASS")]
