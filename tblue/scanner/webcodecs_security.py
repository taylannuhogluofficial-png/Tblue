"""WebCodecs API security scanner — passive analysis of VideoDecoder/VideoEncoder usage."""
import re
from .base import BaseScanner

_WC_DECODER_RE   = re.compile(r'new\s+(?:VideoDecoder|AudioDecoder|ImageDecoder)\s*\(', re.I)
_WC_ENCODER_RE   = re.compile(r'new\s+(?:VideoEncoder|AudioEncoder)\s*\(', re.I)
_WC_ANY_RE       = re.compile(r'(?:VideoDecoder|AudioDecoder|ImageDecoder|VideoEncoder|AudioEncoder)\b', re.I)

# Encoded output sent to remote
_WC_ENCODE_SEND_RE = re.compile(
    r'(?:VideoEncoder|AudioEncoder)[^;]{0,300}(?:fetch|XMLHttpRequest|sendBeacon)', re.I | re.S
)

# Decoding data from URL parameters (SSRF-style)
_WC_DECODE_URL_PARAM_RE = re.compile(
    r'(?:VideoDecoder|AudioDecoder|ImageDecoder)[^;]{0,300}(?:location\.|searchParams|getParam)', re.I | re.S
)

# Error/output side channel — measuring decode timing
_WC_TIMING_RE = re.compile(
    r'(?:VideoDecoder|AudioDecoder)[^;]{0,200}(?:performance\.now|Date\.now)', re.I | re.S
)

# Shared ArrayBuffer with Worker without SharedArrayBuffer guards
_WC_SHARED_BUFFER_RE = re.compile(r'SharedArrayBuffer[^;]{0,200}(?:VideoDecoder|AudioDecoder|VideoEncoder)', re.I | re.S)

# Missing error handler on decode — hard crash possible
_WC_NO_ERROR_HANDLER_RE = re.compile(
    r'new\s+(?:VideoDecoder|AudioDecoder)\s*\(\s*\{[^}]*output\s*:[^}]*\}', re.I | re.S
)
_WC_ERROR_HANDLER_RE = re.compile(r'error\s*:\s*(?:function|\w+\s*=>|\w+)', re.I)


class WebCodecsSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "webcodecs_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _WC_ANY_RE.search(body):
            return [self._result(url, "webcodecs_not_used", "INFO",
                                 detail="WebCodecs API not detected")]

        results = []

        if _WC_ENCODE_SEND_RE.search(body):
            results.append(self._result(url, "webcodecs_encoded_data_transmitted", "WARN",
                                        detail="Encoded audio/video data transmitted to remote endpoint"))

        if _WC_DECODE_URL_PARAM_RE.search(body):
            results.append(self._result(url, "webcodecs_decode_from_url_param", "FAIL",
                                        detail="Decoder input sourced from URL parameters — potential decoder confusion"))

        if _WC_TIMING_RE.search(body):
            results.append(self._result(url, "webcodecs_timing_side_channel", "WARN",
                                        detail="Decode timing measured — potential side-channel fingerprinting"))

        if _WC_SHARED_BUFFER_RE.search(body):
            results.append(self._result(url, "webcodecs_shared_array_buffer", "WARN",
                                        detail="SharedArrayBuffer used with WebCodecs — Spectre-adjacent timing risk"))

        if _WC_NO_ERROR_HANDLER_RE.search(body) and not _WC_ERROR_HANDLER_RE.search(body):
            results.append(self._result(url, "webcodecs_missing_error_handler", "WARN",
                                        detail="VideoDecoder/AudioDecoder instantiated without error handler"))

        if not results:
            results.append(self._result(url, "webcodecs_found_no_issues", "PASS",
                                        detail="WebCodecs API usage appears safe"))

        return results
