"""Web Locks API security — locks held indefinitely (DoS), missing abort signal, lock name enumeration."""
import re
from .base import BaseScanner

_LOCK_REQUEST_RE = re.compile(r'navigator\.locks\.request\s*\(', re.I)
_LOCK_QUERY_RE = re.compile(r'navigator\.locks\.query\s*\(\s*\)', re.I)
_LOCK_STEAL_RE = re.compile(r'steal\s*:\s*true', re.I)
_LOCK_IF_AVAILABLE_RE = re.compile(r'ifAvailable\s*:\s*true', re.I)
_LOCK_SIGNAL_RE = re.compile(r'signal\s*:', re.I)
_LOCK_MODE_EXCLUSIVE_RE = re.compile(r'mode\s*:\s*["\']exclusive["\']', re.I)
_INFINITE_LOCK_RE = re.compile(
    r'navigator\.locks\.request\s*\([^)]*(?:async\s+\(\s*\)\s*=>\s*\{[^}]*\}|\(\s*\)\s*=>\s*\{[^}]*while\s*\(true\))',
    re.I | re.S,
)
_LOCK_NAME_FROM_INPUT_RE = re.compile(
    r'navigator\.locks\.request\s*\(\s*(?:location\.|searchParams|getParam|getElementById|querySelector)',
    re.I,
)
_LOCK_QUERY_STATE_SEND_RE = re.compile(
    r'navigator\.locks\.query[^;]{0,200}(?:fetch|XMLHttpRequest|sendBeacon)',
    re.I | re.S,
)


class LockAPISecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "lock_api_no_response", "PASS", detail="No response")]

        body = resp.text or ""

        if not _LOCK_REQUEST_RE.search(body) and not _LOCK_QUERY_RE.search(body):
            return [self._result(url, "lock_api_not_used", "PASS",
                                 detail="Web Locks API not detected on this page")]

        lock_requests = len(_LOCK_REQUEST_RE.findall(body))

        if _LOCK_STEAL_RE.search(body):
            results.append(self._result(url, "lock_api_steal_true", "WARN",
                                        detail="navigator.locks.request() with steal:true — "
                                               "forcibly breaking held locks can cause data corruption "
                                               "in concurrent operations; only use steal in explicit recovery scenarios"))

        if lock_requests > 0 and not _LOCK_SIGNAL_RE.search(body):
            results.append(self._result(url, "lock_api_no_abort_signal", "WARN",
                                        detail="navigator.locks.request() without signal (AbortSignal) — "
                                               "lock requests with no abort signal can queue indefinitely, "
                                               "causing tab resource exhaustion and DoS if the lock holder crashes"))

        if _LOCK_NAME_FROM_INPUT_RE.search(body):
            results.append(self._result(url, "lock_api_name_from_input", "WARN",
                                        detail="Lock name derived from URL parameter or user input — "
                                               "attacker controls lock namespace, enabling lock contention DoS "
                                               "or information leakage via lock state"))

        if _LOCK_QUERY_STATE_SEND_RE.search(body):
            results.append(self._result(url, "lock_api_state_transmitted", "INFO",
                                        detail="Lock state from navigator.locks.query() sent to server — "
                                               "lock names may reveal application feature states or user context"))

        if not results:
            results.append(self._result(url, "lock_api_found_no_issues", "PASS",
                                        detail="Web Locks API used but no security issues detected"))
        return results
