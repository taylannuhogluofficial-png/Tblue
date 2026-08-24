"""FormData API security scanner — passive detection of multipart upload data leaks."""
import re
from .base import BaseScanner

_FD_ANY_RE = re.compile(
    r'(?:new\s+FormData\s*\(|FormData\b|formData\.append\b|formData\.set\b)',
    re.I,
)

_FD_SENSITIVE_APPEND_RE = re.compile(
    r'(?:formData|FormData)[^;]{0,100}\.append\s*\([^,)]+,\s*[^)]*(?:token|password|secret|auth|key)[^)]*\)',
    re.I,
)

_FD_URL_FROM_PARAM_RE = re.compile(
    r'(?:formData|FormData)[^;]{0,100}\.append\s*\([^)]*(?:searchParams|location\.hash)[^)]*\)',
    re.I,
)

_FD_FILE_EXFIL_RE = re.compile(
    r'(?:formData|FormData)[^;]{0,200}\.append\s*\([^,)]+,\s*[^)]*(?:file|blob|File|Blob)[^)]*\)[^;]{0,200}'
    r'(?:fetch|XMLHttpRequest|https?://)',
    re.I,
)

_FD_ENDPOINT_FROM_PARAM_RE = re.compile(
    r'fetch\s*\([^,)]*(?:searchParams|location\.hash)[^,)]*,\s*\{[^}]*body\s*:\s*formData',
    re.I,
)


class FormDataSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "form_data_not_used", "PASS")]

        body = resp.text

        if not _FD_ANY_RE.search(body):
            return [self._result(url, "form_data_not_used", "PASS")]

        findings = []

        if _FD_SENSITIVE_APPEND_RE.search(body):
            findings.append(self._result(
                url, "form_data_sensitive_field", "FAIL",
                detail="FormData appends credentials/token as form field — sensitive data in multipart upload.",
            ))

        if _FD_URL_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "form_data_field_from_url_param", "WARN",
                detail="FormData field value sourced from URL parameter — attacker-controlled form submission data.",
            ))

        if _FD_FILE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "form_data_file_upload_exfil", "WARN",
                detail="FormData with File/Blob uploaded to external endpoint — file exfiltration via FormData.",
            ))

        return findings or [self._result(url, "form_data_safe", "PASS")]
