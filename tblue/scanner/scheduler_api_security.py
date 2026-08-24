"""Scheduler API security scanner — postTask timing oracle, sensitive data in task payloads."""
import re
from .base import BaseScanner

_SCHED_ANY_RE = re.compile(
    r'(?:scheduler\.postTask\b|TaskController\b|TaskSignal\b|scheduler\.yield\b)',
    re.I
)

# postTask with sensitive data transmitted in callback
_SCHED_DATA_EXFIL_RE = re.compile(
    r'scheduler\.postTask\s*\([^;]{0,400}(?:fetch|sendBeacon|XMLHttpRequest)[^;]{0,200}(?:localStorage|sessionStorage|cookie|token|password)',
    re.I | re.S
)

# Timing oracle — postTask result timing to infer computation or auth state
_SCHED_TIMING_ORACLE_RE = re.compile(
    r'scheduler\.postTask\s*\([^;]{0,300}performance\.now[^;]{0,200}(?:fetch|sendBeacon)',
    re.I | re.S
)

# TaskController.abort() used with URL parameter — attacker can abort user tasks
_SCHED_ABORT_FROM_PARAM_RE = re.compile(
    r'TaskController[^;]{0,400}(?:searchParams|location\.search|getParam)[^;]{0,200}abort\s*\(',
    re.I | re.S
)

# Sensitive data passed directly in postTask callback (inline function with secret)
_SCHED_SENSITIVE_TASK_RE = re.compile(
    r'scheduler\.postTask\s*\([^;]{0,200}(?:apiKey|authToken|password|secret|sessionId)',
    re.I | re.S
)

# postTask priority derived from URL parameter — priority manipulation
_SCHED_PRIORITY_PARAM_RE = re.compile(
    r'scheduler\.postTask\s*\([^)]*\)[^;]{0,200}priority[^;]{0,200}(?:searchParams|getParam|location\.search)',
    re.I | re.S
)


class SchedulerAPISecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "scheduler_api_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _SCHED_ANY_RE.search(body):
            return [self._result(url, "scheduler_api_not_used", "INFO",
                                 detail="Scheduler API not detected")]

        results = []

        if _SCHED_DATA_EXFIL_RE.search(body):
            results.append(self._result(url, "scheduler_task_data_exfiltrated", "FAIL",
                                        detail="postTask callback transmits data from localStorage/cookies to remote — sensitive task data exfiltration"))

        if _SCHED_SENSITIVE_TASK_RE.search(body):
            results.append(self._result(url, "scheduler_sensitive_data_in_task", "WARN",
                                        detail="postTask callback contains sensitive variable names (apiKey, authToken, password) — credential exposure in scheduled task"))

        if _SCHED_TIMING_ORACLE_RE.search(body):
            results.append(self._result(url, "scheduler_timing_oracle", "WARN",
                                        detail="postTask timing measured via performance.now and transmitted — timing oracle enabling side-channel attacks"))

        if _SCHED_ABORT_FROM_PARAM_RE.search(body):
            results.append(self._result(url, "scheduler_abort_from_url_param", "WARN",
                                        detail="TaskController.abort() triggered by URL parameter — attacker can abort legitimate user tasks via URL manipulation"))

        if _SCHED_PRIORITY_PARAM_RE.search(body):
            results.append(self._result(url, "scheduler_priority_from_url_param", "WARN",
                                        detail="postTask priority derived from URL parameter — attacker boosts malicious task priority or degrades legitimate task execution"))

        if not results:
            results.append(self._result(url, "scheduler_api_found_no_issues", "PASS",
                                        detail="Scheduler API usage appears safe"))

        return results
