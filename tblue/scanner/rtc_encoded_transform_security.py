"""RTCInsertableStreams / Encoded Transform security scanner — passive detection of WebRTC media interception."""
import re
from .base import BaseScanner

_RET_ANY_RE = re.compile(
    r'(?:RTCRtpSender\.createEncodedStreams\b|RTCRtpReceiver\.createEncodedStreams\b|'
    r'createEncodedStreams\s*\(|RTCEncodedVideoFrame\b|RTCEncodedAudioFrame\b|'
    r'SFrameTransform\b|RTCRtpScriptTransform\b|insertableStreams\b)',
    re.I,
)

_RET_FRAME_EXFIL_RE = re.compile(
    r'(?:RTCEncodedVideoFrame|RTCEncodedAudioFrame|readable|writable)\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|WebSocket)',
    re.I,
)

_RET_KEY_FROM_PARAM_RE = re.compile(
    r'(?:SFrameTransform|RTCRtpScriptTransform)\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_RET_WEAK_CRYPTO_RE = re.compile(
    r'(?:SFrameTransform|createEncodedStreams)\b[^;]{0,300}'
    r'(?:Math\.random|Date\.now|xor\b|rot13\b|base64)',
    re.I,
)

_RET_PASSTHROUGH_RE = re.compile(
    r'createEncodedStreams\s*\([^;]{0,300}'
    r'(?:readable\.pipeTo\s*\(\s*writable|pipeTo\s*\(\s*writable)',
    re.I,
)


class RTCEncodedTransformSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "rtc_encoded_transform_not_used", "PASS")]

        body = resp.text

        if not _RET_ANY_RE.search(body):
            return [self._result(url, "rtc_encoded_transform_not_used", "PASS")]

        findings = []

        if _RET_FRAME_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "rtc_encoded_frame_exfiltrated", "FAIL",
                detail="RTCEncodedVideoFrame/AudioFrame data transmitted to remote — WebRTC media intercepted via insertable streams.",
            ))

        if _RET_KEY_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "rtc_transform_key_from_param", "FAIL",
                detail="SFrameTransform / RTCRtpScriptTransform configured from URL parameter — attacker-controlled encryption key material.",
            ))

        if _RET_WEAK_CRYPTO_RE.search(body):
            findings.append(self._result(
                url, "rtc_encoded_transform_weak_crypto", "WARN",
                detail="RTCInsertableStreams transform uses Math.random/xor/base64 instead of SubtleCrypto — weak DIY encryption on media frames.",
            ))

        if _RET_PASSTHROUGH_RE.search(body):
            findings.append(self._result(
                url, "rtc_encoded_transform_passthrough", "WARN",
                detail="Encoded streams piped directly from readable to writable — insertable streams used without encryption (passthrough tap).",
            ))

        return findings or [self._result(url, "rtc_encoded_transform_safe", "PASS")]
