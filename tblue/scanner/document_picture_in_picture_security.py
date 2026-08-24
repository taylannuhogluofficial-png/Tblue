"""Document Picture-in-Picture API security scanner — passive detection of document PiP misuse."""
import re
from .base import BaseScanner

_DPIP_ANY_RE = re.compile(
    r'(?:documentPictureInPicture\b|window\.documentPictureInPicture\b|'
    r'requestWindow\s*\(|pipWindow\b|PictureInPictureWindow\b|'
    r'documentPictureInPicture\.requestWindow\s*\()',
    re.I,
)

_DPIP_AUTO_OPEN_RE = re.compile(
    r'requestWindow\s*\([^;]{0,300}'
    r'(?:DOMContentLoaded|onload|immediately|addEventListener|autoOpen)',
    re.I,
)

_DPIP_PHISHING_OVERLAY_RE = re.compile(
    r'requestWindow\s*\([^;]{0,400}'
    r'(?:password|login|credential|auth|payment|card)',
    re.I,
)

_DPIP_CONTENT_FROM_PARAM_RE = re.compile(
    r'(?:documentPictureInPicture|requestWindow|pipWindow)\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_DPIP_EXFIL_ON_ENTER_RE = re.compile(
    r'(?:enterpictureinpicture|pipWindow)\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class DocumentPictureInPictureSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "document_pip_not_used", "PASS")]

        body = resp.text

        if not _DPIP_ANY_RE.search(body):
            return [self._result(url, "document_pip_not_used", "PASS")]

        findings = []

        if _DPIP_AUTO_OPEN_RE.search(body):
            findings.append(self._result(
                url, "document_pip_auto_opened", "FAIL",
                detail="documentPictureInPicture.requestWindow() triggered automatically — unprompted document PiP window creation.",
            ))

        if _DPIP_PHISHING_OVERLAY_RE.search(body):
            findings.append(self._result(
                url, "document_pip_phishing_overlay", "FAIL",
                detail="Document PiP window opened with auth/login/payment content — floating PiP window used to spoof trusted UI.",
            ))

        if _DPIP_CONTENT_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "document_pip_content_from_param", "WARN",
                detail="Document PiP configuration sourced from URL parameter — attacker-controlled PiP window content.",
            ))

        if _DPIP_EXFIL_ON_ENTER_RE.search(body):
            findings.append(self._result(
                url, "document_pip_exfil_on_enter", "WARN",
                detail="Data transmitted when entering PiP mode — PiP entry event used to trigger covert exfiltration.",
            ))

        return findings or [self._result(url, "document_pip_safe", "PASS")]
