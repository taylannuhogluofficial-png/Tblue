"""Drag and Drop API security scanner — passive detection of drag data exfiltration."""
import re
from .base import BaseScanner

_DD_ANY_RE = re.compile(
    r'(?:dragstart\b|dataTransfer\b|\.getData\s*\(|\.setData\s*\(|drop\s*event)',
    re.I,
)

_DD_DATA_EXFIL_RE = re.compile(
    r'dataTransfer\.getData\s*\([^)]*\)[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_DD_SENSITIVE_SET_RE = re.compile(
    r'dataTransfer\.setData\s*\([^,)]+,\s*[^)]*(?:token|password|auth|cookie|secret)[^)]*\)',
    re.I,
)

_DD_FILE_EXFIL_RE = re.compile(
    r'dataTransfer\.files[^;]{0,200}(?:fetch|sendBeacon|FormData)',
    re.I,
)

_DD_URL_FROM_PARAM_RE = re.compile(
    r'(?:dragstart|drop)[^;]{0,200}(?:searchParams|location\.hash)[^;]{0,200}dataTransfer',
    re.I,
)


class DragDropSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "drag_drop_not_used", "PASS")]

        body = resp.text

        if not _DD_ANY_RE.search(body):
            return [self._result(url, "drag_drop_not_used", "PASS")]

        findings = []

        if _DD_DATA_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "drag_drop_data_exfiltrated", "FAIL",
                detail="Drag-and-drop data retrieved via dataTransfer.getData() and transmitted — drag data exfiltration.",
            ))

        if _DD_SENSITIVE_SET_RE.search(body):
            findings.append(self._result(
                url, "drag_drop_sensitive_data_set", "WARN",
                detail="Drag transfer sets sensitive data (token/password/auth) — credentials exposed via drag operation.",
            ))

        if _DD_FILE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "drag_drop_file_exfiltrated", "FAIL",
                detail="Dropped files (dataTransfer.files) transmitted to remote endpoint — file exfiltration via drag-and-drop.",
            ))

        return findings or [self._result(url, "drag_drop_safe", "PASS")]
