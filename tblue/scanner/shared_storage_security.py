"""Shared Storage API security scanner — passive detection of cross-site data leaks."""
import re
from .base import BaseScanner

_SS_ANY_RE = re.compile(
    r'(?:window\.sharedStorage\b|sharedStorage\.set\b|sharedStorage\.get\b|sharedStorage\.selectURL\b|SharedStorageWorklet\b)',
    re.I,
)

_SS_SENSITIVE_WRITE_RE = re.compile(
    r'sharedStorage\.set\s*\([^)]*(?:token|password|userId|email|phone)[^)]*\)',
    re.I,
)

_SS_SELECT_URL_EXFIL_RE = re.compile(
    r'sharedStorage\.selectURL[^;]{0,300}(?:fetch|sendBeacon|analytics)',
    re.I,
)

_SS_DATA_FROM_PARAM_RE = re.compile(
    r'sharedStorage\.set\s*\([^)]*(?:searchParams|location\.hash)[^)]*\)',
    re.I,
)

_SS_CROSS_SITE_READ_RE = re.compile(
    r'sharedStorage\.get\s*\([^)]*\)[^;]{0,200}(?:fetch|sendBeacon|postMessage)',
    re.I,
)


class SharedStorageSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "shared_storage_not_used", "PASS")]

        body = resp.text

        if not _SS_ANY_RE.search(body):
            return [self._result(url, "shared_storage_not_used", "PASS")]

        findings = []

        if _SS_SENSITIVE_WRITE_RE.search(body):
            findings.append(self._result(
                url, "shared_storage_sensitive_data_written", "FAIL",
                detail="Sensitive PII/credentials written to Shared Storage — cross-site data exposure risk.",
            ))

        if _SS_SELECT_URL_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "shared_storage_select_url_exfil", "WARN",
                detail="selectURL result transmitted externally — cross-site user profiling via URL selection oracle.",
            ))

        if _SS_DATA_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "shared_storage_data_from_url_param", "FAIL",
                detail="Shared Storage value sourced from URL parameter — attacker-controlled cross-site data injection.",
            ))

        if _SS_CROSS_SITE_READ_RE.search(body):
            findings.append(self._result(
                url, "shared_storage_read_exfiltrated", "FAIL",
                detail="Shared Storage value read and transmitted externally — cross-site data exfiltration.",
            ))

        return findings or [self._result(url, "shared_storage_safe", "PASS")]
