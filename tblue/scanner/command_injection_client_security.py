"""Command Injection Client-side scanner — detection of shell/OS command injection patterns in client JS."""
import re
from .base import BaseScanner

_CI_ANY_RE = re.compile(
    r'(?:child_process\b|exec\s*\(|spawn\s*\(|execSync\s*\(|'
    r'shell\s*:\s*true\b|shelljs\b|execa\s*\()',
    re.I,
)

_CI_FROM_PARAM_RE = re.compile(
    r'(?:exec|spawn|execSync|execa)\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href|userInput)',
    re.I,
)

_CI_CONCAT_CMD_RE = re.compile(
    r'(?:exec|spawn|execSync)\s*\(\s*["\'][^"\']{0,100}["\'\s]\s*\+\s*[^;]{0,200}'
    r'(?:userInput|inputValue|filename|filepath|username)',
    re.I,
)

_CI_SHELL_TRUE_FROM_PARAM_RE = re.compile(
    r'shell\s*:\s*true\b[^;]{0,300}'
    r'(?:searchParams|location\.hash|userInput)',
    re.I,
)

_CI_RESULT_EXFIL_RE = re.compile(
    r'(?:exec|spawn|execSync)\b[^;]{0,400}'
    r'(?:sendBeacon|fetch\s*\([^)]{0,100}analytics|XMLHttpRequest)',
    re.I,
)


class CommandInjectionClientSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "command_injection_client_not_used", "PASS")]

        body = resp.text
        if not _CI_ANY_RE.search(body):
            return [self._result(url, "command_injection_client_not_used", "PASS")]

        findings = []

        if _CI_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "command_injection_from_param", "FAIL",
                detail="exec()/spawn()/execSync() called with URL parameter/user input — OS command injection via attacker-controlled command argument in client-side Node.js/Electron.",
            ))

        if _CI_CONCAT_CMD_RE.search(body):
            findings.append(self._result(
                url, "command_injection_string_concat", "FAIL",
                detail="Shell command built via string concatenation with userInput/filename — classic command injection; attacker inserts shell metacharacters (;, |, &&) to chain commands.",
            ))

        if _CI_SHELL_TRUE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "command_injection_shell_true", "FAIL",
                detail="spawn/exec with {shell:true} and user-controlled input — shell:true enables shell metacharacter interpretation; combined with user input enables OS command injection.",
            ))

        if _CI_RESULT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "command_injection_result_exfil", "WARN",
                detail="Shell command result transmitted via fetch/sendBeacon/XMLHttpRequest — OS command output exfiltrated to remote endpoint (reconnaissance or data theft).",
            ))

        return findings or [self._result(url, "command_injection_client_safe", "PASS")]
