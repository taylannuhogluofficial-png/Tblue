"""Object URL / Blob URL security scanner — passive detection of blob: URL misuse."""
import re
from .base import BaseScanner

_OU_ANY_RE = re.compile(
    r'(?:URL\.createObjectURL\s*\(|URL\.revokeObjectURL\s*\(|blob:\b|'
    r'createObjectURL\s*\(|Blob\s*\(\s*\[)',
    re.I,
)

_OU_SENSITIVE_BLOB_EXFIL_RE = re.compile(
    r'URL\.createObjectURL\s*\([^;]{0,200}'
    r'(?:token|password|auth|secret|cookie|localStorage|sessionStorage)',
    re.I,
)

_OU_BLOB_FROM_PARAM_RE = re.compile(
    r'(?:Blob\s*\(\s*\[|createObjectURL\s*\()[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_OU_BLOB_WORKER_INJECT_RE = re.compile(
    r'URL\.createObjectURL\s*\([^;]{0,200}Worker\s*\('
    r'|Worker\s*\([^;]{0,200}URL\.createObjectURL\s*\(',
    re.I,
)

_OU_NO_REVOKE_SENSITIVE_RE = re.compile(
    r'URL\.createObjectURL\s*\([^;]{0,300}'
    r'(?:token|password|auth|secret|cookie)[^;]{0,500}'
    r'(?!URL\.revokeObjectURL)',
    re.I,
)


class ObjectURLSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "object_url_not_used", "PASS")]

        body = resp.text

        if not _OU_ANY_RE.search(body):
            return [self._result(url, "object_url_not_used", "PASS")]

        findings = []

        if _OU_SENSITIVE_BLOB_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "object_url_sensitive_data_blob", "FAIL",
                detail="URL.createObjectURL() creates blob from credentials/tokens — sensitive data encoded in blob: URL.",
            ))

        if _OU_BLOB_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "object_url_blob_from_param", "FAIL",
                detail="Blob content sourced from URL parameter — attacker-controlled blob: URL content injection.",
            ))

        if _OU_BLOB_WORKER_INJECT_RE.search(body):
            findings.append(self._result(
                url, "object_url_worker_code_injection", "WARN",
                detail="URL.createObjectURL() used to create a Worker — dynamic worker code injection via blob: URL.",
            ))

        return findings or [self._result(url, "object_url_safe", "PASS")]
