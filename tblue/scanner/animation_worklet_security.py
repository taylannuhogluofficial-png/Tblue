"""Animation Worklet (CSS Houdini) security scanner — passive detection of animation worklet attacks."""
import re
from .base import BaseScanner

_AWK_ANY_RE = re.compile(
    r'(?:CSS\.animationWorklet\b|animationWorklet\.addModule\s*\(|'
    r'registerAnimator\s*\(|WorkletAnimation\b|new\s+WorkletAnimation\s*\(|'
    r'AnimationWorkletGlobalScope\b)',
    re.I,
)

_AWK_MODULE_FROM_PARAM_RE = re.compile(
    r'animationWorklet\.addModule\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_AWK_TIMING_EXFIL_RE = re.compile(
    r'(?:WorkletAnimation|registerAnimator)\b[^;]{0,400}'
    r'(?:performance\.now|localTime|currentTime)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|postMessage)',
    re.I,
)

_AWK_EXTERNAL_MODULE_RE = re.compile(
    r'animationWorklet\.addModule\s*\(\s*["\']https?://',
    re.I,
)

_AWK_INPUT_EXFIL_RE = re.compile(
    r'registerAnimator\s*\([^;]{0,400}'
    r'(?:effect\.getComputedTiming|currentTime|localTime)[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)


class AnimationWorkletSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "animation_worklet_not_used", "PASS")]

        body = resp.text

        if not _AWK_ANY_RE.search(body):
            return [self._result(url, "animation_worklet_not_used", "PASS")]

        findings = []

        if _AWK_MODULE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "animation_worklet_module_from_param", "FAIL",
                detail="animationWorklet.addModule() URL sourced from URL parameter — attacker-controlled animation worklet code loading.",
            ))

        if _AWK_EXTERNAL_MODULE_RE.search(body):
            findings.append(self._result(
                url, "animation_worklet_external_module", "WARN",
                detail="Animation worklet loaded from external URL — third-party code runs in animation worklet sandbox.",
            ))

        if _AWK_TIMING_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "animation_worklet_timing_exfil", "WARN",
                detail="WorkletAnimation timing values transmitted to remote — animation timeline used as covert timing channel.",
            ))

        if _AWK_INPUT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "animation_worklet_input_exfil", "WARN",
                detail="registerAnimator() computed timing data transmitted to remote — animation worklet used for timing surveillance.",
            ))

        return findings or [self._result(url, "animation_worklet_safe", "PASS")]
