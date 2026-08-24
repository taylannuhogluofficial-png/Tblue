"""Document Picture-in-Picture API security scanner — sensitive DOM in floating window, no isolation."""
import re
from .base import BaseScanner

_DPIP_REQUEST_RE = re.compile(r'documentPictureInPicture\.requestWindow\s*\(', re.I)
_DPIP_ANY_RE     = re.compile(r'documentPictureInPicture\b', re.I)

# Sensitive content cloned into PiP window
_DPIP_SENSITIVE_RE = re.compile(
    r'documentPictureInPicture[^;]{0,400}(?:password|token|auth|secret|card|CVV|ssn)',
    re.I | re.S
)

# PiP window accesses parent DOM
_DPIP_PARENT_ACCESS_RE = re.compile(
    r'(?:pipWindow|pip\.document)[^;]{0,200}(?:opener|parent|top|window\[)', re.I | re.S
)

# PiP content sent to remote
_DPIP_SEND_RE = re.compile(
    r'(?:pipWindow|pip\.document)[^;]{0,300}(?:fetch|XMLHttpRequest|sendBeacon)', re.I | re.S
)

# Auto-open PiP on page load
_DPIP_AUTO_OPEN_RE = re.compile(
    r'(?:DOMContentLoaded|window\.onload|addEventListener\s*\(\s*["\']load["\'])[^;]{0,400}documentPictureInPicture',
    re.I | re.S
)

# Missing permission handling
_DPIP_NO_PERM_RE = re.compile(r'documentPictureInPicture\.requestWindow\s*\(', re.I)
_DPIP_PERM_RE    = re.compile(r'(?:NotAllowedError|catch|permission|gesture)', re.I)


class DocumentPIPSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "document_pip_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _DPIP_ANY_RE.search(body):
            return [self._result(url, "document_pip_not_used", "INFO",
                                 detail="Document Picture-in-Picture API not detected")]

        results = []

        if _DPIP_AUTO_OPEN_RE.search(body):
            results.append(self._result(url, "document_pip_auto_open", "FAIL",
                                        detail="Document PiP opened on page load — requires user gesture"))

        if _DPIP_SENSITIVE_RE.search(body):
            results.append(self._result(url, "document_pip_sensitive_content", "FAIL",
                                        detail="Sensitive content (password/token/card) placed in floating PiP window — visible across desktops"))

        if _DPIP_PARENT_ACCESS_RE.search(body):
            results.append(self._result(url, "document_pip_parent_access", "WARN",
                                        detail="PiP window accesses parent/opener — potential cross-context DOM access"))

        if _DPIP_SEND_RE.search(body):
            results.append(self._result(url, "document_pip_data_transmitted", "WARN",
                                        detail="Data from PiP window context transmitted to remote endpoint"))

        if _DPIP_NO_PERM_RE.search(body) and not _DPIP_PERM_RE.search(body):
            results.append(self._result(url, "document_pip_no_permission_handling", "WARN",
                                        detail="requestWindow() used without catching NotAllowedError"))

        if not results:
            results.append(self._result(url, "document_pip_found_no_issues", "PASS",
                                        detail="Document Picture-in-Picture usage appears safe"))

        return results
