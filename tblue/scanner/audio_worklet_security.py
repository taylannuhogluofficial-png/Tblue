"""AudioWorklet security scanner — passive detection of audio API surveillance patterns."""
import re
from .base import BaseScanner

_AW_ANY_RE = re.compile(
    r'(?:AudioWorklet\b|audioWorklet\.addModule\s*\(|AudioWorkletNode\b|'
    r'AudioWorkletProcessor\b|registerProcessor\s*\(|AudioContext\b|OfflineAudioContext\b)',
    re.I,
)

_AW_FINGERPRINT_RE = re.compile(
    r'(?:AudioContext|OfflineAudioContext)\b[^;]{0,400}'
    r'(?:sendBeacon|fetch|XMLHttpRequest|analytics)[^;]{0,200}'
    r'(?:fingerprint|fp|deviceId|userId)',
    re.I,
)

_AW_MIC_EXFIL_RE = re.compile(
    r'AudioWorkletNode\b[^;]{0,400}'
    r'(?:getUserMedia|microphone|MediaStreamSource)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_AW_MODULE_FROM_PARAM_RE = re.compile(
    r'audioWorklet\.addModule\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_AW_TIMING_COVERT_RE = re.compile(
    r'AudioContext\b[^;]{0,300}'
    r'(?:currentTime|baseLatency|outputLatency)[^;]{0,200}'
    r'(?:fetch|sendBeacon|analytics)',
    re.I,
)


class AudioWorkletSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "audio_worklet_not_used", "PASS")]

        body = resp.text

        if not _AW_ANY_RE.search(body):
            return [self._result(url, "audio_worklet_not_used", "PASS")]

        findings = []

        if _AW_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "audio_context_fingerprinting", "FAIL",
                detail="AudioContext characteristics transmitted for device fingerprinting — audio hardware used as identifier.",
            ))

        if _AW_MIC_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "audio_worklet_mic_exfil", "FAIL",
                detail="AudioWorkletNode connected to microphone with network transmission — audio surveillance via Web Audio API.",
            ))

        if _AW_MODULE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "audio_worklet_module_from_param", "FAIL",
                detail="audioWorklet.addModule() URL sourced from URL parameter — attacker-controlled worklet code loading.",
            ))

        if _AW_TIMING_COVERT_RE.search(body):
            findings.append(self._result(
                url, "audio_context_timing_covert_channel", "WARN",
                detail="AudioContext timing properties (currentTime/latency) transmitted to remote — audio clock used as covert channel.",
            ))

        return findings or [self._result(url, "audio_worklet_safe", "PASS")]
