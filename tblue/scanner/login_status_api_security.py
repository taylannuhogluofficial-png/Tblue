"""Login Status API security scanner — passive detection of login state surveillance."""
import re
from .base import BaseScanner

_LS_ANY_RE = re.compile(
    r'(?:navigator\.login\b|LoginStatus\b|setStatus\s*\(\s*["\']logged-in["\']|isLoggedIn\b|login\.setStatus)',
    re.I,
)

_LS_STATUS_EXFIL_RE = re.compile(
    r'navigator\.login[^;]{0,200}(?:fetch|sendBeacon|analytics|XMLHttpRequest)',
    re.I,
)

_LS_FORCED_LOGIN_RE = re.compile(
    r'(?:DOMContentLoaded|pageshow)[^;]{0,300}navigator\.login\.setStatus\s*\(\s*["\']logged-in["\']'
    r'|navigator\.login\.setStatus\s*\(\s*["\']logged-in["\'][^;]{0,100}(?:DOMContentLoaded|pageshow)',
    re.I,
)

_LS_PARAM_CONTROLLED_RE = re.compile(
    r'navigator\.login\.setStatus\s*\([^)]*(?:searchParams|location\.hash)[^)]*\)',
    re.I,
)


class LoginStatusAPISecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "login_status_api_not_used", "PASS")]

        body = resp.text

        if not _LS_ANY_RE.search(body):
            return [self._result(url, "login_status_api_not_used", "PASS")]

        findings = []

        if _LS_STATUS_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "login_status_exfiltrated", "WARN",
                detail="navigator.login state transmitted to remote endpoint — user login status surveillance.",
            ))

        if _LS_FORCED_LOGIN_RE.search(body):
            findings.append(self._result(
                url, "login_status_forced_on_load", "WARN",
                detail="navigator.login.setStatus('logged-in') triggered on page load — false login state injection.",
            ))

        if _LS_PARAM_CONTROLLED_RE.search(body):
            findings.append(self._result(
                url, "login_status_from_url_param", "FAIL",
                detail="Login status set from URL parameter — attacker-controlled login state manipulation.",
            ))

        return findings or [self._result(url, "login_status_api_safe", "PASS")]
