"""Session Fixation security scanner — passive detection of session token acceptance from URL."""
import re
from .base import BaseScanner

_SF_ANY_RE = re.compile(
    r'(?:sessionId\b|session_id\b|JSESSIONID\b|PHPSESSID\b|'
    r'document\.cookie\s*=|\.setItem\s*\(\s*["\']session|'
    r'session\.token\b|sessionToken\b)',
    re.I,
)

_SF_FROM_PARAM_RE = re.compile(
    r'(?:sessionId|session_id|sessionToken|JSESSIONID)\b[^;]{0,300}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_SF_COOKIE_FROM_PARAM_RE = re.compile(
    r'document\.cookie\s*=[^;]{0,300}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_SF_SESSION_STORAGE_FROM_PARAM_RE = re.compile(
    r'(?:sessionStorage|localStorage)\.setItem\s*\(\s*["\']session[^"\']*["\']\s*,[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_SF_SESSION_EXFIL_RE = re.compile(
    r'(?:sessionId|session_id|sessionToken)\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class SessionFixationSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "session_fixation_not_used", "PASS")]

        body = resp.text

        if not _SF_ANY_RE.search(body):
            return [self._result(url, "session_fixation_not_used", "PASS")]

        findings = []

        if _SF_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "session_fixation_token_from_param", "FAIL",
                detail="Session ID/token read from URL parameter — classic session fixation: attacker sets victim's session ID before authentication, then hijacks session.",
            ))

        if _SF_COOKIE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "session_fixation_cookie_from_param", "FAIL",
                detail="document.cookie set from URL parameter value — session cookie injected via URL parameter enables session fixation attack.",
            ))

        if _SF_SESSION_STORAGE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "session_fixation_storage_from_param", "FAIL",
                detail="sessionStorage/localStorage session value set from URL parameter — attacker-controlled session token stored in browser storage (session fixation via storage).",
            ))

        if _SF_SESSION_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "session_token_exfil", "FAIL",
                detail="sessionId/sessionToken transmitted via fetch/sendBeacon — active session token exfiltrated to remote endpoint enabling session hijacking.",
            ))

        return findings or [self._result(url, "session_fixation_safe", "PASS")]
