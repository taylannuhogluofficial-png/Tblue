"""Clipboard Advanced security scanner — passive detection of clipboard API data exfiltration."""
import re
from .base import BaseScanner

_CA_ANY_RE = re.compile(
    r'(?:navigator\.clipboard\b|clipboard\.readText\s*\(|'
    r'clipboard\.read\s*\(|clipboard\.writeText\s*\(|'
    r'clipboard\.write\s*\(|ClipboardItem\b|'
    r'clipboardData\.getData\s*\(|clipboardData\.setData\s*\()',
    re.I,
)

_CA_READ_EXFIL_RE = re.compile(
    r'clipboard\.readText\s*\([^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_CA_PASTE_EXFIL_RE = re.compile(
    r'clipboardData\.getData\s*\([^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_CA_FROM_PARAM_RE = re.compile(
    r'clipboard\.writeText\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_CA_CREDENTIALS_IN_CLIPBOARD_RE = re.compile(
    r'clipboard\.writeText\s*\([^;]{0,200}'
    r'(?:password|token|secret|auth|credential|apiKey)',
    re.I,
)


class ClipboardAdvancedSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "clipboard_advanced_not_used", "PASS")]

        body = resp.text

        if not _CA_ANY_RE.search(body):
            return [self._result(url, "clipboard_advanced_not_used", "PASS")]

        findings = []

        if _CA_READ_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "clipboard_read_exfil", "FAIL",
                detail="clipboard.readText() result transmitted via fetch/sendBeacon — clipboard contents (passwords, tokens, PII) silently exfiltrated on focus/interaction.",
            ))

        if _CA_PASTE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "clipboard_paste_event_exfil", "FAIL",
                detail="clipboardData.getData() result transmitted via fetch/sendBeacon — paste event clipboard contents exfiltrated (steals pasted passwords and sensitive data).",
            ))

        if _CA_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "clipboard_write_from_param", "WARN",
                detail="clipboard.writeText() content from URL parameter — attacker-controlled text written to clipboard (clipboard hijacking for phishing).",
            ))

        if _CA_CREDENTIALS_IN_CLIPBOARD_RE.search(body):
            findings.append(self._result(
                url, "clipboard_write_credentials", "WARN",
                detail="clipboard.writeText() contains password/token/credential — sensitive data written to clipboard, accessible to any focused page or extension.",
            ))

        return findings or [self._result(url, "clipboard_advanced_safe", "PASS")]
