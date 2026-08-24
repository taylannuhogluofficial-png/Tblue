"""AudioDecoder / AudioEncoder (WebCodecs) security scanner — passive detection of audio codec attacks."""
import re
from .base import BaseScanner

_AD_ANY_RE = re.compile(
    r'(?:new\s+AudioDecoder\s*\(|new\s+AudioEncoder\s*\(|AudioDecoder\b|AudioEncoder\b|'
    r'EncodedAudioChunk\b|AudioData\b|audioDecoder\.decode\s*\()',
    re.I,
)

_AD_DATA_EXFIL_RE = re.compile(
    r'AudioData\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|WebSocket)',
    re.I,
)

_AD_SOURCE_FROM_PARAM_RE = re.compile(
    r'(?:AudioDecoder|AudioEncoder)\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_AD_TIMING_ORACLE_RE = re.compile(
    r'(?:AudioDecoder|AudioEncoder)\b[^;]{0,300}'
    r'(?:performance\.now|Date\.now|PerformanceObserver)[^;]{0,200}'
    r'(?:fetch|sendBeacon|analytics)',
    re.I,
)

_AD_MIC_ENCODE_EXFIL_RE = re.compile(
    r'AudioEncoder\b[^;]{0,400}'
    r'(?:getUserMedia|microphone|MediaStreamSource)[^;]{0,200}'
    r'(?:fetch|sendBeacon|WebSocket)',
    re.I,
)


class AudioDecoderSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "audio_decoder_not_used", "PASS")]

        body = resp.text

        if not _AD_ANY_RE.search(body):
            return [self._result(url, "audio_decoder_not_used", "PASS")]

        findings = []

        if _AD_DATA_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "audio_data_exfiltrated", "FAIL",
                detail="AudioData transmitted to remote endpoint — decoded audio frame content exfiltrated via WebCodecs.",
            ))

        if _AD_SOURCE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "audio_decoder_source_from_param", "FAIL",
                detail="AudioDecoder/AudioEncoder configured from URL parameter — attacker-controlled audio codec configuration.",
            ))

        if _AD_TIMING_ORACLE_RE.search(body):
            findings.append(self._result(
                url, "audio_decoder_timing_oracle", "WARN",
                detail="AudioDecoder timing measured and transmitted — audio decode latency used as hardware timing oracle.",
            ))

        if _AD_MIC_ENCODE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "audio_encoder_mic_exfil", "FAIL",
                detail="AudioEncoder connected to microphone input with network transmission — mic audio encoded and exfiltrated.",
            ))

        return findings or [self._result(url, "audio_decoder_safe", "PASS")]
