"""ImageDecoder (WebCodecs) security scanner — passive detection of image codec security issues."""
import re
from .base import BaseScanner

_ID_ANY_RE = re.compile(
    r'(?:new\s+ImageDecoder\s*\(|ImageDecoder\b|ImageTrack\b|ImageTrackList\b|'
    r'imageDecoder\.decode\s*\(|ImageBitmap\b|createImageBitmap\s*\()',
    re.I,
)

_ID_FRAME_EXFIL_RE = re.compile(
    r'ImageDecoder\b[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|canvas\.toDataURL|toBlob)',
    re.I,
)

_ID_SOURCE_FROM_PARAM_RE = re.compile(
    r'ImageDecoder\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_ID_TIMING_ORACLE_RE = re.compile(
    r'ImageDecoder\b[^;]{0,300}'
    r'(?:performance\.now|Date\.now|PerformanceObserver)[^;]{0,200}'
    r'(?:fetch|sendBeacon|analytics)',
    re.I,
)

_ID_CROSS_ORIGIN_DECODE_RE = re.compile(
    r'ImageDecoder\b[^;]{0,300}'
    r'(?:crossOrigin|cross-origin|fetch\s*\(\s*["\']https?://|no-cors)',
    re.I,
)


class ImageDecoderSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "image_decoder_not_used", "PASS")]

        body = resp.text

        if not _ID_ANY_RE.search(body):
            return [self._result(url, "image_decoder_not_used", "PASS")]

        findings = []

        if _ID_FRAME_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "image_decoder_frame_exfiltrated", "FAIL",
                detail="ImageDecoder decoded frame transmitted to remote — image pixel data exfiltrated via WebCodecs.",
            ))

        if _ID_SOURCE_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "image_decoder_source_from_param", "FAIL",
                detail="ImageDecoder data source from URL parameter — attacker-controlled image data fed to decoder.",
            ))

        if _ID_TIMING_ORACLE_RE.search(body):
            findings.append(self._result(
                url, "image_decoder_timing_oracle", "WARN",
                detail="ImageDecoder timing measured and transmitted — image decode latency used as hardware timing oracle.",
            ))

        if _ID_CROSS_ORIGIN_DECODE_RE.search(body):
            findings.append(self._result(
                url, "image_decoder_cross_origin", "WARN",
                detail="ImageDecoder decoding cross-origin image data without CORP — untrusted image content decoded via WebCodecs.",
            ))

        return findings or [self._result(url, "image_decoder_safe", "PASS")]
