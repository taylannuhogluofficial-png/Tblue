"""Screen Wake Lock API security scanner — persistent screen-on, battery drain, activity leakage."""
import re
from .base import BaseScanner

_SWL_REQUEST_RE = re.compile(r'navigator\.wakeLock\.request\s*\(', re.I)
_SWL_ANY_RE     = re.compile(r'(?:navigator\.wakeLock|WakeLockSentinel)\b', re.I)

# Wake lock held indefinitely (never released)
_SWL_NO_RELEASE_RE = re.compile(r'navigator\.wakeLock\.request\s*\(', re.I)
_SWL_RELEASE_RE    = re.compile(r'\.release\s*\(\s*\)', re.I)

# Wake lock acquired on page load automatically
_SWL_AUTO_ACQUIRE_RE = re.compile(
    r'(?:DOMContentLoaded|window\.onload|addEventListener\s*\(\s*["\']load["\'])[^;]{0,400}wakeLock',
    re.I | re.S
)

# Wake lock state transmitted to analytics
_SWL_SEND_RE = re.compile(
    r'(?:wakeLock|WakeLockSentinel)[^;]{0,200}(?:fetch|XMLHttpRequest|sendBeacon|analytics)',
    re.I | re.S
)

# Wake lock in a loop — repeated re-acquisition
_SWL_LOOP_RE = re.compile(
    r'(?:setInterval|while\s*\([^)]*\))[^;]{0,300}wakeLock', re.I | re.S
)

# Page visibility change not handled — wake lock should release on hidden
_SWL_NO_VISIBILITY_RE = re.compile(r'navigator\.wakeLock\b', re.I)
_SWL_VISIBILITY_RE    = re.compile(r'visibilitychange\b', re.I)


class ScreenWakeLockSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "screen_wake_lock_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _SWL_ANY_RE.search(body):
            return [self._result(url, "screen_wake_lock_not_used", "INFO",
                                 detail="Screen Wake Lock API not detected")]

        results = []

        if _SWL_AUTO_ACQUIRE_RE.search(body):
            results.append(self._result(url, "screen_wake_lock_auto_acquire", "WARN",
                                        detail="Wake lock acquired on page load — screen stays on without user consent"))

        if _SWL_LOOP_RE.search(body):
            results.append(self._result(url, "screen_wake_lock_loop_reacquire", "WARN",
                                        detail="Wake lock re-acquired in loop — prevents device from sleeping indefinitely"))

        if _SWL_NO_RELEASE_RE.search(body) and not _SWL_RELEASE_RE.search(body):
            results.append(self._result(url, "screen_wake_lock_never_released", "WARN",
                                        detail="Wake lock acquired but release() never called — persistent screen-on battery drain"))

        if _SWL_NO_VISIBILITY_RE.search(body) and not _SWL_VISIBILITY_RE.search(body):
            results.append(self._result(url, "screen_wake_lock_no_visibility_handler", "WARN",
                                        detail="Wake lock used without visibilitychange handler — lock may persist when tab is hidden"))

        if _SWL_SEND_RE.search(body):
            results.append(self._result(url, "screen_wake_lock_state_transmitted", "INFO",
                                        detail="Wake lock state transmitted to analytics — passive activity/attention tracking"))

        if not results:
            results.append(self._result(url, "screen_wake_lock_found_no_issues", "PASS",
                                        detail="Screen Wake Lock usage appears safe"))

        return results
