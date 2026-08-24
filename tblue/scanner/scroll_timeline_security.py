"""Scroll Timeline API security scanner — passive detection of scroll-based surveillance."""
import re
from .base import BaseScanner

_ST_ANY_RE = re.compile(
    r'(?:ScrollTimeline\b|new\s+ScrollTimeline\s*\(|ViewTimeline\b|new\s+ViewTimeline\s*\(|'
    r'animation-timeline\b|scroll\s*\(\s*\)|view\s*\(\s*\))',
    re.I,
)

_ST_EXFIL_RE = re.compile(
    r'ScrollTimeline[^;]{0,300}(?:currentTime|progress)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_ST_READ_POSITION_RE = re.compile(
    r'(?:ScrollTimeline|ViewTimeline)[^;]{0,200}'
    r'(?:currentTime|phase|progress)[^;]{0,200}'
    r'(?:token|password|auth|login|account)',
    re.I,
)

_ST_VIEW_TIMELINE_EXFIL_RE = re.compile(
    r'ViewTimeline[^;]{0,300}(?:startOffset|endOffset|currentTime)[^;]{0,200}'
    r'(?:fetch|sendBeacon|analytics)',
    re.I,
)

_ST_PARAM_CONTROLLED_RE = re.compile(
    r'(?:ScrollTimeline|ViewTimeline)[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class ScrollTimelineSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "scroll_timeline_not_used", "PASS")]

        body = resp.text

        if not _ST_ANY_RE.search(body):
            return [self._result(url, "scroll_timeline_not_used", "PASS")]

        findings = []

        if _ST_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "scroll_timeline_position_exfiltrated", "FAIL",
                detail="ScrollTimeline currentTime/progress transmitted to remote — user scroll position surveillance.",
            ))

        if _ST_READ_POSITION_RE.search(body):
            findings.append(self._result(
                url, "scroll_timeline_auth_correlation", "WARN",
                detail="Scroll timeline state correlated with auth/login context — scroll position used for activity inference.",
            ))

        if _ST_VIEW_TIMELINE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "view_timeline_data_exfiltrated", "WARN",
                detail="ViewTimeline offset/currentTime transmitted — element visibility timing data exfiltrated.",
            ))

        if _ST_PARAM_CONTROLLED_RE.search(body):
            findings.append(self._result(
                url, "scroll_timeline_from_url_param", "FAIL",
                detail="ScrollTimeline/ViewTimeline configured from URL parameter — attacker-controlled animation timeline.",
            ))

        return findings or [self._result(url, "scroll_timeline_safe", "PASS")]
