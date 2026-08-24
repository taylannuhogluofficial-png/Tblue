"""Compression Streams API security scanner — BREACH-like side channels, decompressing untrusted data."""
import re
from .base import BaseScanner

_CS_COMPRESS_RE   = re.compile(r'new\s+CompressionStream\s*\(', re.I)
_CS_DECOMPRESS_RE = re.compile(r'new\s+DecompressionStream\s*\(', re.I)
_CS_ANY_RE        = re.compile(r'(?:Compression|Decompression)Stream\b', re.I)

# Secret mixed with attacker-controlled data then compressed and sent — BREACH pattern
_CS_MIXED_COMPRESS_RE = re.compile(
    r'CompressionStream[^;]{0,400}(?:cookie|token|secret|Authorization|Bearer)', re.I | re.S
)

# Decompressing data from URL parameter — zip bomb or parser confusion
_CS_DECOMPRESS_URL_RE = re.compile(
    r'DecompressionStream[^;]{0,300}(?:location\.|searchParams|getParam|fetch)', re.I | re.S
)

# Compressed size used as oracle (length comparison)
_CS_SIZE_ORACLE_RE = re.compile(
    r'(?:byteLength|length)[^;]{0,200}CompressionStream|CompressionStream[^;]{0,200}(?:byteLength|length)',
    re.I | re.S
)

# Compressed output transmitted
_CS_SEND_RE = re.compile(
    r'CompressionStream[^;]{0,400}(?:fetch|XMLHttpRequest|sendBeacon)', re.I | re.S
)

# Decompress without size limit — zip bomb
_CS_NO_SIZE_LIMIT_RE = re.compile(r'DecompressionStream\b', re.I)
_CS_SIZE_LIMIT_RE    = re.compile(
    r'(?:maxSize|MAX_SIZE|limit|maxLength|byteLength\s*[<>]=?\s*\d)', re.I
)


class CompressionStreamsSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "compression_streams_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _CS_ANY_RE.search(body):
            return [self._result(url, "compression_streams_not_used", "INFO",
                                 detail="Compression Streams API not detected")]

        results = []

        if _CS_MIXED_COMPRESS_RE.search(body):
            results.append(self._result(url, "compression_streams_breach_pattern", "FAIL",
                                        detail="Secrets mixed with user-controlled data before compression — BREACH-like oracle"))

        if _CS_SIZE_ORACLE_RE.search(body):
            results.append(self._result(url, "compression_streams_size_oracle", "WARN",
                                        detail="Compressed size compared or transmitted — length-based side channel risk"))

        if _CS_DECOMPRESS_URL_RE.search(body):
            results.append(self._result(url, "compression_streams_decompress_untrusted", "FAIL",
                                        detail="DecompressionStream fed data from URL/fetch — zip bomb or parser confusion risk"))

        if _CS_SEND_RE.search(body):
            results.append(self._result(url, "compression_streams_compressed_data_sent", "WARN",
                                        detail="Compressed output transmitted to remote — review for sensitive content"))

        if _CS_NO_SIZE_LIMIT_RE.search(body) and not _CS_SIZE_LIMIT_RE.search(body):
            results.append(self._result(url, "compression_streams_no_size_limit", "WARN",
                                        detail="DecompressionStream used without apparent size limit — zip bomb risk"))

        if not results:
            results.append(self._result(url, "compression_streams_found_no_issues", "PASS",
                                        detail="Compression Streams API usage appears safe"))

        return results
