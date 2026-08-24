"""Document Picture-in-Picture API security scanner — sensitive content in PiP window, cross-origin access."""
import re
from .base import BaseScanner

_PIP_ANY_RE = re.compile(
    r'(?:documentPictureInPicture\b|requestWindow\s*\(|PictureInPictureWindow\b|pipWindow\b)',
    re.I
)

# PiP window URL derived from URL parameter — attacker opens arbitrary content in PiP
_PIP_URL_FROM_PARAM_RE = re.compile(
    r'requestWindow\s*\([^)]*(?:searchParams|location\.search|getParam)',
    re.I
)

# Sensitive content moved to PiP window (auth form, payment details)
_PIP_SENSITIVE_CONTENT_RE = re.compile(
    r'(?:documentPictureInPicture|requestWindow|pipWindow)[^;]{0,400}(?:password|creditCard|token|auth|payment|billing)',
    re.I | re.S
)

# PiP window accesses parent document DOM (cross-context DOM read)
_PIP_PARENT_DOM_RE = re.compile(
    r'pipWindow[^;]{0,400}(?:opener\.|parent\.|top\.)[^;]{0,200}(?:document|localStorage|sessionStorage)',
    re.I | re.S
)

# Data exfiltrated through PiP window events
_PIP_EXFIL_VIA_EVENTS_RE = re.compile(
    r'(?:documentPictureInPicture|pipWindow)[^;]{0,400}(?:postMessage|fetch|sendBeacon|XMLHttpRequest)[^;]{0,200}(?:token|auth|cookie|session)',
    re.I | re.S
)

# PiP window auto-opened on page load — unexpected overlay without user gesture
_PIP_AUTO_OPEN_RE = re.compile(
    r'(?:DOMContentLoaded|window\.onload|addEventListener\s*\(\s*["\']load["\'])[^;]{0,500}requestWindow',
    re.I | re.S
)


class DocumentPIPApiSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "document_pip_api_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _PIP_ANY_RE.search(body):
            return [self._result(url, "document_pip_api_not_used", "INFO",
                                 detail="Document Picture-in-Picture API not detected")]

        results = []

        if _PIP_URL_FROM_PARAM_RE.search(body):
            results.append(self._result(url, "pip_window_url_from_param", "WARN",
                                        detail="PiP window request derived from URL parameter — attacker controls what content appears in PiP overlay"))

        if _PIP_SENSITIVE_CONTENT_RE.search(body):
            results.append(self._result(url, "pip_sensitive_content_exposed", "WARN",
                                        detail="Sensitive content (password/auth/payment) moved to PiP window — displayed in uncontrolled overlay context with different origin checks"))

        if _PIP_PARENT_DOM_RE.search(body):
            results.append(self._result(url, "pip_accesses_parent_dom", "FAIL",
                                        detail="PiP window accesses parent document DOM via opener/parent — cross-context DOM read bypasses expected isolation"))

        if _PIP_EXFIL_VIA_EVENTS_RE.search(body):
            results.append(self._result(url, "pip_exfiltrates_via_events", "WARN",
                                        detail="PiP window or documentPiP transmits auth/session data via postMessage or network — cross-context data exfiltration"))

        if _PIP_AUTO_OPEN_RE.search(body):
            results.append(self._result(url, "pip_auto_opened_on_load", "WARN",
                                        detail="Document PiP window requested on page load without user gesture — unexpected overlay opens automatically"))

        if not results:
            results.append(self._result(url, "document_pip_api_found_no_issues", "PASS",
                                        detail="Document Picture-in-Picture API usage appears safe"))

        return results
