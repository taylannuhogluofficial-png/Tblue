"""Account Enumeration security scanner — passive detection of user existence disclosure."""
import re
from .base import BaseScanner

_AE_ANY_RE = re.compile(
    r'(?:user.?not.?found|account.?not.?exist|'
    r'email.?not.?registered|username.?taken|'
    r'invalid.?username|user.?does.?not.?exist|'
    r'no.?account.?found|email.?already.?in.?use)',
    re.I,
)

_AE_DIFFERENT_MSG_RE = re.compile(
    r'(?:user.?not.?found|account.?not.?exist|email.?not.?registered)[^.!?]{0,200}'
    r'(?:wrong.?password|incorrect.?password|invalid.?password)',
    re.I,
)

_AE_TIMING_EXFIL_RE = re.compile(
    r'(?:user.?not.?found|account.?not.?exist)\b[^;]{0,400}'
    r'(?:Date\.now|performance\.now)',
    re.I,
)

_AE_EXISTS_CHECK_RE = re.compile(
    r'(?:checkEmail|checkUsername|emailExists|userExists)\s*\([^;]{0,300}'
    r'(?:fetch|XMLHttpRequest)',
    re.I,
)

_AE_REGISTRATION_REVEAL_RE = re.compile(
    r'(?:username.?taken|email.?already.?in.?use)[^;]{0,200}'
    r'(?:displayError|showError|errorMessage|innerHTML)',
    re.I,
)


class AccountEnumerationSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "account_enumeration_not_used", "PASS")]

        body = resp.text

        if not _AE_ANY_RE.search(body):
            return [self._result(url, "account_enumeration_not_used", "PASS")]

        findings = []

        if _AE_DIFFERENT_MSG_RE.search(body):
            findings.append(self._result(
                url, "account_enumeration_different_messages", "WARN",
                detail="Different error messages for 'user not found' vs 'wrong password' — login error differentiation enables username enumeration attack.",
            ))

        if _AE_TIMING_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "account_enumeration_timing_oracle", "WARN",
                detail="'user not found' code path includes timing measurement — different response times for existing vs non-existing users enables timing-based enumeration.",
            ))

        if _AE_EXISTS_CHECK_RE.search(body):
            findings.append(self._result(
                url, "account_enumeration_check_endpoint", "WARN",
                detail="checkEmail()/checkUsername() calls fetch/XHR — real-time existence check endpoint is an enumeration oracle (confirms which accounts exist).",
            ))

        if _AE_REGISTRATION_REVEAL_RE.search(body):
            findings.append(self._result(
                url, "account_enumeration_registration_reveal", "WARN",
                detail="Registration form reveals 'username taken'/'email already in use' — confirms which accounts already exist (registration-based enumeration).",
            ))

        return findings or [self._result(url, "account_enumeration_safe", "PASS")]
