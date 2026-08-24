"""Web Share API security scanner — passive detection of unintended data sharing."""
import re
from .base import BaseScanner

_WS_ANY_RE = re.compile(
    r'(?:navigator\.share\s*\(|navigator\.canShare\s*\(|'
    r'Web\s*Share\b|share\s*API|ShareData\b)',
    re.I,
)

_WS_CREDENTIALS_SHARED_RE = re.compile(
    r'navigator\.share\s*\([^;]{0,300}'
    r'(?:password|token|secret|auth|credential|apiKey)',
    re.I,
)

_WS_FROM_PARAM_RE = re.compile(
    r'navigator\.share\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_WS_FILES_EXFIL_RE = re.compile(
    r'navigator\.share\s*\([^;]{0,300}'
    r'(?:files\s*:|FileList|File\b|Blob\b)',
    re.I,
)

_WS_SHARE_URL_FROM_PARAM_RE = re.compile(
    r'navigator\.share\s*\(\s*\{[^}]{0,300}'
    r'url\s*:[^}]{0,100}'
    r'(?:searchParams|location\.hash)',
    re.I,
)


class WebShareSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "web_share_not_used", "PASS")]

        body = resp.text

        if not _WS_ANY_RE.search(body):
            return [self._result(url, "web_share_not_used", "PASS")]

        findings = []

        if _WS_CREDENTIALS_SHARED_RE.search(body):
            findings.append(self._result(
                url, "web_share_credentials", "FAIL",
                detail="navigator.share() includes password/token/credential — sensitive data shared via native share sheet to any app (social apps, messaging, email).",
            ))

        if _WS_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "web_share_from_param", "WARN",
                detail="navigator.share() content from URL parameter — attacker-controlled share content enables social engineering via crafted share payload.",
            ))

        if _WS_FILES_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "web_share_files", "WARN",
                detail="navigator.share() includes files:/Blob — file contents shared via native share sheet, potentially exposing private documents.",
            ))

        if _WS_SHARE_URL_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "web_share_url_from_param", "WARN",
                detail="navigator.share() url field from URL parameter — attacker-controlled URL in share payload enables open redirect via native share UI.",
            ))

        return findings or [self._result(url, "web_share_safe", "PASS")]
