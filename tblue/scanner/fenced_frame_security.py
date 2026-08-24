"""Fenced Frame security scanner — passive detection of isolation bypass attempts."""
import re
from .base import BaseScanner

_FF_ANY_RE = re.compile(
    r'(?:<fencedframe\b|HTMLFencedFrameElement\b|fencedframe\b|fence\.reportEvent\b|fence\.setReportEventDataForAutomaticBeacons\b)',
    re.I,
)

_FF_URL_FROM_PARAM_RE = re.compile(
    r'fencedframe[^;]{0,200}(?:src|config)[^;]{0,100}(?:searchParams|location\.hash)',
    re.I,
)

_FF_REPORT_EXFIL_RE = re.compile(
    r'fence\.reportEvent\s*\([^)]*(?:token|userId|email|password)[^)]*\)',
    re.I,
)

_FF_PARENT_COMM_RE = re.compile(
    r'fencedframe[^;]{0,200}(?:postMessage|window\.parent|opener\s*\.)',
    re.I,
)

_FF_OPAQUE_BYPASS_RE = re.compile(
    r'fencedframe[^;]{0,300}(?:document\.cookie|localStorage|sessionStorage)',
    re.I,
)


class FencedFrameSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "fenced_frame_not_used", "PASS")]

        body = resp.text

        if not _FF_ANY_RE.search(body):
            return [self._result(url, "fenced_frame_not_used", "PASS")]

        findings = []

        if _FF_URL_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "fenced_frame_url_from_param", "FAIL",
                detail="Fenced Frame src/config URL derived from URL parameter — attacker-controlled frame content.",
            ))

        if _FF_REPORT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "fenced_frame_report_sensitive_data", "FAIL",
                detail="fence.reportEvent() transmits sensitive PII/credentials — Fenced Frame reporting misuse.",
            ))

        if _FF_PARENT_COMM_RE.search(body):
            findings.append(self._result(
                url, "fenced_frame_parent_communication_attempt", "WARN",
                detail="Fenced Frame code attempts postMessage/parent access — Fenced Frame isolation bypass attempt.",
            ))

        if _FF_OPAQUE_BYPASS_RE.search(body):
            findings.append(self._result(
                url, "fenced_frame_storage_access_attempt", "WARN",
                detail="Fenced Frame accesses cookies/localStorage — attempts to break opaque storage isolation.",
            ))

        return findings or [self._result(url, "fenced_frame_safe", "PASS")]
