"""Web Locks API security scanner — lock contention timing oracle, lock name injection, DoS via held locks."""
import re
from .base import BaseScanner

_WL_ANY_RE = re.compile(
    r'(?:navigator\.locks\b|LockManager\b|locks\.request\s*\(|locks\.query\s*\(\s*\))',
    re.I
)

# Lock name derived from URL parameter — attacker locks arbitrary named resources
_WL_NAME_FROM_PARAM_RE = re.compile(
    r'locks\.request\s*\([^)]*(?:searchParams|location\.search|getParam|location\.hash)',
    re.I
)

# Lock contention timing measured and transmitted — side-channel to detect critical section execution
_WL_TIMING_ORACLE_RE = re.compile(
    r'locks\.request[^;]{0,300}(?:performance\.now|Date\.now)[^;]{0,300}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I | re.S
)

# locks.query() used to enumerate held locks and transmit — system lock state exfiltration
_WL_QUERY_EXFIL_RE = re.compile(
    r'locks\.query\s*\(\s*\)[^;]{0,300}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I | re.S
)

# Lock held indefinitely (no release) — locks.request with never-resolving callback = resource DoS
_WL_NEVER_RELEASE_RE = re.compile(
    r'locks\.request\s*\([^)]*\)[^;]{0,400}new\s+Promise\s*\(\s*\(\s*\)\s*=>\s*\{?\s*\}?\s*\)',
    re.I | re.S
)

# Sensitive data processed inside lock callback and transmitted
_WL_SENSITIVE_IN_LOCK_RE = re.compile(
    r'locks\.request[^;]{0,500}(?:token|password|apiKey|sessionId)[^;]{0,200}(?:fetch|sendBeacon)',
    re.I | re.S
)


class WebLocksSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "web_locks_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _WL_ANY_RE.search(body):
            return [self._result(url, "web_locks_not_used", "INFO",
                                 detail="Web Locks API not detected")]

        results = []

        if _WL_NAME_FROM_PARAM_RE.search(body):
            results.append(self._result(url, "web_lock_name_from_url_param", "FAIL",
                                        detail="Lock name derived from URL parameter — attacker can acquire or block named locks via URL manipulation"))

        if _WL_TIMING_ORACLE_RE.search(body):
            results.append(self._result(url, "web_lock_timing_oracle", "WARN",
                                        detail="Lock acquisition timing measured and transmitted — contention timing reveals when other tabs are in critical sections (side-channel)"))

        if _WL_QUERY_EXFIL_RE.search(body):
            results.append(self._result(url, "web_lock_state_exfiltrated", "WARN",
                                        detail="locks.query() result transmitted to remote — currently held/pending locks disclosed (reveals cross-tab application state)"))

        if _WL_NEVER_RELEASE_RE.search(body):
            results.append(self._result(url, "web_lock_never_released", "WARN",
                                        detail="Lock acquired with never-resolving callback — resource lock held indefinitely, causing application-wide deadlock or DoS"))

        if _WL_SENSITIVE_IN_LOCK_RE.search(body):
            results.append(self._result(url, "web_lock_sensitive_data_exfil", "WARN",
                                        detail="Sensitive data (token/password/apiKey) processed in lock callback and transmitted — credentials exfiltrated inside exclusive lock section"))

        if not results:
            results.append(self._result(url, "web_locks_found_no_issues", "PASS",
                                        detail="Web Locks API usage appears safe"))

        return results
