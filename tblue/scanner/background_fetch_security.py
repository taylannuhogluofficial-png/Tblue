"""Background Fetch API security scanner — passive detection of background exfiltration."""
import re
from .base import BaseScanner

_BF_ANY_RE = re.compile(
    r'(?:backgroundFetch\.fetch\b|BackgroundFetchManager\b|bgFetch\b|backgroundFetch\.get\b)',
    re.I,
)

_BF_URL_FROM_PARAM_RE = re.compile(
    r'backgroundFetch\.fetch\s*\([^)]*(?:searchParams|location\.hash|location\.href)[^)]*\)',
    re.I,
)

_BF_SENSITIVE_UPLOAD_RE = re.compile(
    r'backgroundFetch\.fetch[^;]{0,300}(?:token|password|cookie|localStorage|sessionStorage)[^;]{0,200}',
    re.I,
)

_BF_EXFIL_RE = re.compile(
    r'backgroundFetch\.fetch[^;]{0,200}(?:POST|PUT)[^;]{0,200}(?:token|credentials|auth)',
    re.I,
)

_BF_LARGE_PAYLOAD_RE = re.compile(
    r'backgroundFetch\.fetch[^;]{0,300}(?:getDirectory|getFile|blob|arrayBuffer)[^;]{0,200}',
    re.I,
)


class BackgroundFetchSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "background_fetch_not_used", "PASS")]

        body = resp.text

        if not _BF_ANY_RE.search(body):
            return [self._result(url, "background_fetch_not_used", "PASS")]

        findings = []

        if _BF_URL_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "background_fetch_url_from_param", "FAIL",
                detail="Background Fetch URL sourced from URL parameter — SSRF via background channel.",
            ))

        if _BF_SENSITIVE_UPLOAD_RE.search(body):
            findings.append(self._result(
                url, "background_fetch_sensitive_upload", "FAIL",
                detail="Background Fetch uploads sensitive credentials/storage data — covert exfiltration channel.",
            ))

        if _BF_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "background_fetch_credential_exfil", "FAIL",
                detail="Background Fetch POST/PUT includes auth/token data — background credential exfiltration.",
            ))

        if _BF_LARGE_PAYLOAD_RE.search(body):
            findings.append(self._result(
                url, "background_fetch_file_exfil", "WARN",
                detail="Background Fetch transmits file/blob data — potential large-scale file exfiltration pattern.",
            ))

        return findings or [self._result(url, "background_fetch_safe", "PASS")]
