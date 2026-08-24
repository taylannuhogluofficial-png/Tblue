"""ArrayBuffer security scanner — passive detection of ArrayBuffer/DataView misuse."""
import re
from .base import BaseScanner

_AB_ANY_RE = re.compile(
    r'(?:new\s+ArrayBuffer\s*\(|ArrayBuffer\b|DataView\b|new\s+DataView\s*\(|'
    r'buffer\.byteLength\b|dataView\.get(?:Uint8|Int8|Uint16|Int16|Uint32|Float32|Float64)\s*\(|'
    r'dataView\.set(?:Uint8|Int8|Uint16|Int16|Uint32|Float32|Float64)\s*\()',
    re.I,
)

_AB_SENSITIVE_DATA_EXFIL_RE = re.compile(
    r'ArrayBuffer\b[^;]{0,400}'
    r'(?:password|token|secret|auth|credential)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_AB_FROM_PARAM_RE = re.compile(
    r'(?:new\s+ArrayBuffer\s*\(|new\s+DataView\s*\()[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_AB_DATAVIEW_EXFIL_RE = re.compile(
    r'dataView\.get(?:Uint8|Int8|Uint16|Uint32|Float64)\s*\([^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_AB_SHARED_BUFFER_RACE_RE = re.compile(
    r'SharedArrayBuffer\b[^;]{0,400}'
    r'(?:Atomics\.store|Atomics\.load|Atomics\.notify|Atomics\.wait)',
    re.I,
)


class ArrayBufferSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "array_buffer_not_used", "PASS")]

        body = resp.text

        if not _AB_ANY_RE.search(body):
            return [self._result(url, "array_buffer_not_used", "PASS")]

        findings = []

        if _AB_SENSITIVE_DATA_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "array_buffer_credentials_exfil", "FAIL",
                detail="ArrayBuffer containing password/token/credential transmitted via fetch/sendBeacon — sensitive binary data exfiltrated.",
            ))

        if _AB_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "array_buffer_from_param", "WARN",
                detail="ArrayBuffer/DataView created from URL parameter values — attacker-controlled binary buffer size or content.",
            ))

        if _AB_DATAVIEW_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "array_buffer_dataview_exfil", "WARN",
                detail="DataView.getUint8/getUint16/getFloat64() results transmitted via fetch/analytics — binary memory values exfiltrated via DataView.",
            ))

        if _AB_SHARED_BUFFER_RACE_RE.search(body):
            findings.append(self._result(
                url, "array_buffer_shared_atomics_race", "WARN",
                detail="SharedArrayBuffer used with Atomics.store/load/notify — shared memory with Atomics enables high-resolution timing for Spectre-class attacks.",
            ))

        return findings or [self._result(url, "array_buffer_safe", "PASS")]
