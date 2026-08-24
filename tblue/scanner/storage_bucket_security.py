"""Storage Bucket API security scanner — passive detection of persistent isolated storage misuse."""
import re
from .base import BaseScanner

_SB_ANY_RE = re.compile(
    r'(?:navigator\.storageBuckets\b|StorageBucketManager\b|storageBuckets\.open\b|storageBuckets\.keys\b)',
    re.I,
)

_SB_SENSITIVE_DATA_RE = re.compile(
    r'storageBuckets\.open\s*\([^)]*\)[^;]{0,300}(?:setItem|put|add)\s*\([^)]*(?:token|password|auth|secret)[^)]*\)',
    re.I,
)

_SB_NAME_FROM_PARAM_RE = re.compile(
    r'storageBuckets\.open\s*\([^)]*(?:searchParams|location\.hash)[^)]*\)',
    re.I,
)

_SB_ENUMERATE_EXFIL_RE = re.compile(
    r'storageBuckets\.keys\s*\(\s*\)[^;]{0,200}(?:fetch|sendBeacon|analytics)',
    re.I,
)

_SB_PERSIST_SENSITIVE_RE = re.compile(
    r'storageBuckets\.open\s*\([^)]*persisted\s*:\s*true[^)]*\)[^;]{0,300}(?:token|password|auth)',
    re.I,
)


class StorageBucketSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "storage_bucket_not_used", "PASS")]

        body = resp.text

        if not _SB_ANY_RE.search(body):
            return [self._result(url, "storage_bucket_not_used", "PASS")]

        findings = []

        if _SB_SENSITIVE_DATA_RE.search(body):
            findings.append(self._result(
                url, "storage_bucket_sensitive_data_stored", "FAIL",
                detail="Storage Bucket stores credentials/tokens — sensitive data in persistent isolated bucket.",
            ))

        if _SB_NAME_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "storage_bucket_name_from_url_param", "FAIL",
                detail="Storage Bucket name sourced from URL parameter — attacker-controlled bucket access/creation.",
            ))

        if _SB_ENUMERATE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "storage_bucket_keys_exfiltrated", "WARN",
                detail="storageBuckets.keys() result transmitted to remote — bucket inventory exfiltration.",
            ))

        return findings or [self._result(url, "storage_bucket_safe", "PASS")]
