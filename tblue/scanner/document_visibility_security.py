"""Document Visibility API security scanner — tab state tracking, payment flow detection."""
import re
from .base import BaseScanner

_DV_ANY_RE = re.compile(
    r'(?:document\.visibilityState\b|document\.hidden\b|visibilitychange\b|Page Visibility)',
    re.I
)

# visibilitychange event used to transmit user tab state to analytics
_DV_STATE_EXFIL_RE = re.compile(
    r'visibilitychange[^;]{0,300}(?:visibilityState|document\.hidden)[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I | re.S
)

# Tab focus timing measured and sent — precise user attention tracking
_DV_TIMING_TRACK_RE = re.compile(
    r'visibilitychange[^;]{0,300}(?:Date\.now|performance\.now)[^;]{0,300}(?:fetch|sendBeacon|analytics)',
    re.I | re.S
)

# visibilitychange used to pause/resume payment — payment flow visibility detection
_DV_PAYMENT_DETECT_RE = re.compile(
    r'visibilitychange[^;]{0,300}(?:payment|checkout|order|card|billing|invoice)',
    re.I | re.S
)

# Tab switching detected and sensitive data cleared (positive behavior — detect for completeness)
_DV_SENSITIVE_CLEAR_RE = re.compile(
    r'visibilitychange[^;]{0,300}(?:hidden|invisible)[^;]{0,300}(?:clear|remove|delete|null|undefined)[^;]{0,200}(?:token|password|key|secret)',
    re.I | re.S
)

# User "away time" aggregated and exfiltrated
_DV_AWAY_TIME_EXFIL_RE = re.compile(
    r'visibilitychange[^;]{0,500}(?:awayTime|hiddenTime|offTime|inactiveTime)[^;]{0,200}(?:fetch|sendBeacon)',
    re.I | re.S
)


class DocumentVisibilitySecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "document_visibility_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _DV_ANY_RE.search(body):
            return [self._result(url, "document_visibility_not_used", "INFO",
                                 detail="Document Visibility API not detected")]

        results = []

        if _DV_STATE_EXFIL_RE.search(body):
            results.append(self._result(url, "visibility_state_exfiltrated", "WARN",
                                        detail="Tab visibility state transmitted to analytics — user tab-switching behaviour tracked on remote server"))

        if _DV_TIMING_TRACK_RE.search(body):
            results.append(self._result(url, "visibility_timing_tracked", "WARN",
                                        detail="Tab focus duration measured and transmitted — precise user attention time tracked and exfiltrated"))

        if _DV_PAYMENT_DETECT_RE.search(body):
            results.append(self._result(url, "visibility_payment_flow_detection", "WARN",
                                        detail="Visibility change correlated with payment/checkout flow — payment process timing monitored via tab visibility"))

        if _DV_AWAY_TIME_EXFIL_RE.search(body):
            results.append(self._result(url, "visibility_away_time_exfiltrated", "WARN",
                                        detail="User 'away time' (time tab was hidden) measured and transmitted — user inactivity/absence surveillance"))

        if _DV_SENSITIVE_CLEAR_RE.search(body):
            results.append(self._result(url, "visibility_sensitive_data_cleared", "INFO",
                                        detail="Sensitive data cleared when tab becomes hidden — good practice, verify implementation is complete"))

        if not results:
            results.append(self._result(url, "document_visibility_found_no_issues", "PASS",
                                        detail="Document Visibility API usage appears safe"))

        return results
