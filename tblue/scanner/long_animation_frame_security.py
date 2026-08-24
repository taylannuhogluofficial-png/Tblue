"""Long Animation Frame (LoAF) API security scanner — passive detection of timing side-channels."""
import re
from .base import BaseScanner

_LOAF_ANY_RE = re.compile(
    r'(?:long-animation-frame\b|LoAF\b|PerformanceLongAnimationFrameTiming\b|'
    r'PerformanceObserver[^;]{0,100}["\']long-animation-frame["\'])',
    re.I,
)

_LOAF_EXFIL_RE = re.compile(
    r'["\']long-animation-frame["\'][^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_LOAF_KEYSTROKE_TIMING_RE = re.compile(
    r'["\']long-animation-frame["\'][^;]{0,300}'
    r'(?:keydown|keypress|keyup|input|password|typing)',
    re.I,
)

_LOAF_SCRIPT_ATTRIBUTION_RE = re.compile(
    r'LoAF\b[^;]{0,200}(?:scripts|invokerType|sourceURL|sourceFunctionName)[^;]{0,200}'
    r'(?:fetch|sendBeacon|analytics)',
    re.I,
)

_LOAF_CONTINUOUS_RE = re.compile(
    r'PerformanceObserver[^;]{0,200}["\']long-animation-frame["\'][^;]{0,300}'
    r'(?:setInterval|buffered\s*:\s*true|observe\s*\()',
    re.I,
)


class LongAnimationFrameSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "long_animation_frame_not_used", "PASS")]

        body = resp.text

        if not _LOAF_ANY_RE.search(body):
            return [self._result(url, "long_animation_frame_not_used", "PASS")]

        findings = []

        if _LOAF_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "long_animation_frame_data_exfiltrated", "FAIL",
                detail="Long Animation Frame timing data transmitted to remote — performance side-channel via LoAF API.",
            ))

        if _LOAF_KEYSTROKE_TIMING_RE.search(body):
            findings.append(self._result(
                url, "long_animation_frame_keystroke_timing", "FAIL",
                detail="LoAF timing correlated with keydown/input events — keystroke timing inference via animation frame jitter.",
            ))

        if _LOAF_SCRIPT_ATTRIBUTION_RE.search(body):
            findings.append(self._result(
                url, "long_animation_frame_script_attribution_exfil", "WARN",
                detail="LoAF script attribution (sourceURL/invokerType) transmitted — internal script structure disclosure.",
            ))

        if _LOAF_CONTINUOUS_RE.search(body):
            findings.append(self._result(
                url, "long_animation_frame_continuous_collection", "WARN",
                detail="LoAF entries collected continuously via buffered PerformanceObserver — persistent animation timing surveillance.",
            ))

        return findings or [self._result(url, "long_animation_frame_safe", "PASS")]
