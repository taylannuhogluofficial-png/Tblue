"""MediaRecorder API security scanner — passive detection of silent recording."""
import re
from .base import BaseScanner

_MR_ANY_RE = re.compile(
    r'(?:new\s+MediaRecorder\s*\(|MediaRecorder\b|ondataavailable\b|mediaRecorder\.start\b)',
    re.I,
)

_MR_AUTO_RECORD_RE = re.compile(
    r'(?:DOMContentLoaded|pageshow)[^;]{0,300}(?:mediaRecorder|MediaRecorder)[^;]{0,200}\.start\s*\(',
    re.I,
)

_MR_BLOB_EXFIL_RE = re.compile(
    r'(?:mediaRecorder|MediaRecorder)[^;]{0,300}(?:Blob|ondataavailable)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_MR_STREAM_FROM_PARAM_RE = re.compile(
    r'(?:getUserMedia|getDisplayMedia)[^;]{0,200}(?:searchParams|location\.hash)[^;]{0,200}'
    r'(?:mediaRecorder|MediaRecorder)',
    re.I,
)

_MR_CONTINUOUS_RE = re.compile(
    r'(?:mediaRecorder|MediaRecorder)[^;]{0,200}\.start\s*\(\s*(?:[0-9]+)\s*\)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)


class MediaRecorderSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "media_recorder_not_used", "PASS")]

        body = resp.text

        if not _MR_ANY_RE.search(body):
            return [self._result(url, "media_recorder_not_used", "PASS")]

        findings = []

        if _MR_AUTO_RECORD_RE.search(body):
            findings.append(self._result(
                url, "media_recorder_auto_started", "FAIL",
                detail="MediaRecorder.start() triggered on page load — automatic audio/video recording without explicit user action.",
            ))

        if _MR_BLOB_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "media_recorder_blob_exfiltrated", "FAIL",
                detail="MediaRecorder Blob data transmitted to remote server — recorded media exfiltration.",
            ))

        if _MR_CONTINUOUS_RE.search(body):
            findings.append(self._result(
                url, "media_recorder_continuous_upload", "WARN",
                detail="MediaRecorder.start() with timeslice + fetch/beacon — continuous chunked media upload pattern.",
            ))

        return findings or [self._result(url, "media_recorder_safe", "PASS")]
