"""Clipboard API security scanner — auto clipboard read, content exfiltration, clipboard poisoning."""
import re
from .base import BaseScanner

_CB_READ_RE       = re.compile(r'navigator\.clipboard\.read(?:Text)?\s*\(', re.I)
_CB_WRITE_RE      = re.compile(r'navigator\.clipboard\.write(?:Text)?\s*\(', re.I)
_CB_ANY_RE        = re.compile(r'(?:navigator\.clipboard\b|clipboardData\.getData)', re.I)

# Auto-read clipboard on page load
_CB_AUTO_READ_RE = re.compile(
    r'(?:DOMContentLoaded|window\.onload|addEventListener\s*\(\s*["\']load["\'])[^;]{0,400}'
    r'navigator\.clipboard\.read',
    re.I | re.S
)

# Clipboard content sent to remote
_CB_SEND_RE = re.compile(
    r'(?:clipboard|readText|clipboardText|pasteData)[^;]{0,200}'
    r'(?:fetch|XMLHttpRequest|sendBeacon)',
    re.I | re.S
)

# Analytics receiving clipboard content
_CB_ANALYTICS_RE = re.compile(
    r'(?:gtag|analytics|fbq|mixpanel)[^;]{0,200}(?:clipboard|readText|paste)',
    re.I | re.S
)

# Clipboard poisoning — writing malicious content to clipboard
_CB_POISON_RE = re.compile(
    r'navigator\.clipboard\.writeText\s*\([^)]*(?:javascript:|data:|<script|onclick|onerror)',
    re.I | re.S
)

# Read clipboard from paste event (passive clipboard sniffing)
_CB_PASTE_SNIFF_RE = re.compile(
    r'addEventListener\s*\(\s*["\']paste["\'][^;]{0,300}(?:fetch|XMLHttpRequest|sendBeacon)',
    re.I | re.S
)


class ClipboardAPISecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "clipboard_api_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _CB_ANY_RE.search(body):
            return [self._result(url, "clipboard_api_not_used", "INFO",
                                 detail="Clipboard API not detected")]

        results = []

        if _CB_AUTO_READ_RE.search(body):
            results.append(self._result(url, "clipboard_auto_read", "FAIL",
                                        detail="Clipboard read on page load — reads clipboard without user interaction or awareness"))

        if _CB_PASTE_SNIFF_RE.search(body):
            results.append(self._result(url, "clipboard_paste_sniffing", "WARN",
                                        detail="Paste event handler transmits content — passive clipboard content exfiltration"))

        if _CB_SEND_RE.search(body):
            results.append(self._result(url, "clipboard_content_transmitted", "FAIL",
                                        detail="Clipboard content transmitted to remote server — PII/credential exfiltration risk"))

        if _CB_ANALYTICS_RE.search(body):
            results.append(self._result(url, "clipboard_content_to_analytics", "FAIL",
                                        detail="Clipboard data passed to analytics — third-party exfiltration of sensitive copied content"))

        if _CB_POISON_RE.search(body):
            results.append(self._result(url, "clipboard_poisoning", "FAIL",
                                        detail="Clipboard writeText() injects script/protocol handlers — clipboard poisoning attack"))

        if not results:
            results.append(self._result(url, "clipboard_api_found_no_issues", "PASS",
                                        detail="Clipboard API usage appears safe"))

        return results
