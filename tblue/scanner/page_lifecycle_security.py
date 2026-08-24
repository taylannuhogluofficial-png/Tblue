"""Page Lifecycle API security scanner — passive detection of freeze/discard state exploitation."""
import re
from .base import BaseScanner

_PL_ANY_RE = re.compile(
    r'(?:document\.addEventListener\s*\(\s*["\']freeze["\']|'
    r'document\.addEventListener\s*\(\s*["\']resume["\']|'
    r'visibilityState\b|document\.hidden\b|'
    r'onfreeze\b|onresume\b|wasDiscarded\b|'
    r'document\.addEventListener\s*\(\s*["\']visibilitychange["\'])',
    re.I,
)

_PL_EXFIL_ON_FREEZE_RE = re.compile(
    r'["\']freeze["\']\s*[^;]{0,300}'
    r'(?:sendBeacon|fetch|XMLHttpRequest|localStorage\.setItem|sessionStorage\.setItem)',
    re.I,
)

_PL_VISIBILITY_SURVEILLANCE_RE = re.compile(
    r'visibilitychange\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics|tracking)',
    re.I,
)

_PL_DISCARD_STATE_EXFIL_RE = re.compile(
    r'wasDiscarded\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_PL_KEYSTROKE_ON_HIDDEN_RE = re.compile(
    r'document\.hidden\b[^;]{0,300}'
    r'(?:keydown|keypress|input|keyCode|charCode)',
    re.I,
)


class PageLifecycleSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "page_lifecycle_not_used", "PASS")]

        body = resp.text

        if not _PL_ANY_RE.search(body):
            return [self._result(url, "page_lifecycle_not_used", "PASS")]

        findings = []

        if _PL_EXFIL_ON_FREEZE_RE.search(body):
            findings.append(self._result(
                url, "page_lifecycle_exfil_on_freeze", "WARN",
                detail="Data exfiltrated on page freeze event — sendBeacon/fetch in freeze handler used to drain state on tab close.",
            ))

        if _PL_VISIBILITY_SURVEILLANCE_RE.search(body):
            findings.append(self._result(
                url, "page_lifecycle_visibility_surveillance", "WARN",
                detail="visibilitychange events transmitted to analytics — tab focus/blur patterns used for user attention surveillance.",
            ))

        if _PL_DISCARD_STATE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "page_lifecycle_discard_state_exfil", "WARN",
                detail="wasDiscarded flag transmitted to remote — page discard state used to fingerprint session/navigation patterns.",
            ))

        if _PL_KEYSTROKE_ON_HIDDEN_RE.search(body):
            findings.append(self._result(
                url, "page_lifecycle_keystroke_while_hidden", "FAIL",
                detail="Keydown/input events captured while document.hidden — keyboard surveillance continues even when page is not visible.",
            ))

        return findings or [self._result(url, "page_lifecycle_safe", "PASS")]
