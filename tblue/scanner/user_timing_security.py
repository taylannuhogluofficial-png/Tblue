"""User Timing API security scanner — performance.mark/measure exfiltration and side channels."""
import re
from .base import BaseScanner

_UT_MARK_RE    = re.compile(r'performance\.mark\s*\(', re.I)
_UT_MEASURE_RE = re.compile(r'performance\.measure\s*\(', re.I)
_UT_ANY_RE     = re.compile(r'performance\.(?:mark|measure|getEntriesByName|getEntriesByType)\s*\(', re.I)

# Timing data transmitted
_UT_SEND_RE = re.compile(
    r'performance\.(?:mark|measure|getEntries)[^;]{0,300}(?:fetch|XMLHttpRequest|sendBeacon)',
    re.I | re.S
)

# Duration/mark name transmitted
_UT_DURATION_SEND_RE = re.compile(
    r'(?:duration|startTime|entryType)[^;]{0,200}(?:fetch|XMLHttpRequest|sendBeacon)',
    re.I | re.S
)

# Mark name includes sensitive user path info
_UT_SENSITIVE_MARK_RE = re.compile(
    r'performance\.mark\s*\(\s*["\'][^"\']*(?:user|auth|login|checkout|payment|account)[^"\']*["\']',
    re.I
)

# Timing marks used to probe resource load times (cross-origin timing)
_UT_CROSS_ORIGIN_TIMING_RE = re.compile(
    r'performance\.mark[^;]{0,200}(?:crossOrigin|Cross-Origin|third.party)',
    re.I | re.S
)

# Analytics receiving timing data
_UT_ANALYTICS_RE = re.compile(
    r'(?:gtag|analytics|fbq|mixpanel)[^;]{0,200}(?:duration|startTime|performance\.)',
    re.I | re.S
)


class UserTimingSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "user_timing_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _UT_ANY_RE.search(body):
            return [self._result(url, "user_timing_not_used", "INFO",
                                 detail="User Timing API not detected")]

        results = []

        if _UT_SENSITIVE_MARK_RE.search(body):
            results.append(self._result(url, "user_timing_sensitive_mark_names", "WARN",
                                        detail="Mark names include sensitive user flow labels — exposes feature usage patterns"))

        if _UT_SEND_RE.search(body):
            results.append(self._result(url, "user_timing_entries_transmitted", "WARN",
                                        detail="Performance mark/measure entries transmitted to remote — timing fingerprinting"))

        if _UT_DURATION_SEND_RE.search(body):
            results.append(self._result(url, "user_timing_duration_transmitted", "WARN",
                                        detail="Timing duration/startTime values transmitted — side-channel for user behaviour"))

        if _UT_ANALYTICS_RE.search(body):
            results.append(self._result(url, "user_timing_shared_with_analytics", "FAIL",
                                        detail="Performance timing data sent to analytics — user journey and device profiling"))

        if _UT_CROSS_ORIGIN_TIMING_RE.search(body):
            results.append(self._result(url, "user_timing_cross_origin_probe", "WARN",
                                        detail="Marks used to probe cross-origin resource timing — potential XS-Leak"))

        if not results:
            results.append(self._result(url, "user_timing_found_no_issues", "PASS",
                                        detail="User Timing API usage appears safe"))

        return results
