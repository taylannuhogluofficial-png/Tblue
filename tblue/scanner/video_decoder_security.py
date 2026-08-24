"""VideoDecoder / VideoEncoder API security scanner — passive detection of codec-based attacks."""
import re
from .base import BaseScanner

_VD_ANY_RE = re.compile(
    r'(?:new\s+VideoDecoder\s*\(|new\s+VideoEncoder\s*\(|VideoDecoder\b|VideoEncoder\b|'
    r'EncodedVideoChunk\b|VideoFrame\b|VideoColorSpace\b)',
    re.I,
)

_VD_TIMING_ORACLE_RE = re.compile(
    r'VideoDecoder\b[^;]{0,300}'
    r'(?:performance\.now|Date\.now|PerformanceObserver)[^;]{0,200}'
    r'(?:fetch|sendBeacon|analytics)',
    re.I,
)

_VD_FRAME_EXFIL_RE = re.compile(
    r'VideoFrame\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|canvas\.toDataURL|toBlob)',
    re.I,
)

_VD_PARAM_CONTROLLED_CODEC_RE = re.compile(
    r'(?:VideoDecoder|VideoEncoder)\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href|innerHTML)',
    re.I,
)

_VD_CROSS_ORIGIN_DECODE_RE = re.compile(
    r'EncodedVideoChunk\b[^;]{0,300}'
    r'(?:cross-origin|crossOrigin|fetch\s*\(\s*["\']https?://|no-cors)',
    re.I,
)


class VideoDecoderSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "video_decoder_not_used", "PASS")]

        body = resp.text

        if not _VD_ANY_RE.search(body):
            return [self._result(url, "video_decoder_not_used", "PASS")]

        findings = []

        if _VD_TIMING_ORACLE_RE.search(body):
            findings.append(self._result(
                url, "video_decoder_timing_oracle", "WARN",
                detail="VideoDecoder timing measured and transmitted — codec decode latency used as device/hardware timing oracle.",
            ))

        if _VD_FRAME_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "video_frame_data_exfiltrated", "FAIL",
                detail="VideoFrame content sent to remote endpoint — decoded video frame pixels exfiltrated via network.",
            ))

        if _VD_PARAM_CONTROLLED_CODEC_RE.search(body):
            findings.append(self._result(
                url, "video_codec_from_url_param", "FAIL",
                detail="VideoDecoder/VideoEncoder configured from URL parameter — attacker-controlled codec configuration.",
            ))

        if _VD_CROSS_ORIGIN_DECODE_RE.search(body):
            findings.append(self._result(
                url, "video_cross_origin_decode", "WARN",
                detail="EncodedVideoChunk loaded from cross-origin source — untrusted codec data decoded without CORP validation.",
            ))

        return findings or [self._result(url, "video_decoder_safe", "PASS")]
