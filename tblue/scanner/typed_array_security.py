"""Typed Array security scanner — passive detection of TypedArray misuse for data exfiltration."""
import re
from .base import BaseScanner

_TA_ANY_RE = re.compile(
    r'(?:new\s+(?:Uint8Array|Int8Array|Uint16Array|Int16Array|Uint32Array|Int32Array|'
    r'Float32Array|Float64Array|BigInt64Array|BigUint64Array)\s*\(|'
    r'Uint8Array\b|Float32Array\b|Float64Array\b|Uint32Array\b|'
    r'Int8Array\b|Int16Array\b|Int32Array\b)',
    re.I,
)

_TA_CREDENTIALS_EXFIL_RE = re.compile(
    r'Uint8Array\b[^;]{0,400}'
    r'(?:password|token|secret|auth|credential|key)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_TA_BUFFER_FROM_PARAM_RE = re.compile(
    r'(?:Uint8Array|Int8Array|Float32Array|Float64Array)\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_TA_MEMORY_DUMP_RE = re.compile(
    r'(?:Uint8Array|Int8Array)\b[^;]{0,300}'
    r'(?:buffer\.byteLength|BYTES_PER_ELEMENT)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_TA_WASM_MEMORY_EXFIL_RE = re.compile(
    r'(?:WebAssembly\.Memory|wasmMemory|wasm\.memory)\b[^;]{0,300}'
    r'new\s+Uint8Array\s*\([^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)


class TypedArraySecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "typed_array_not_used", "PASS")]

        body = resp.text

        if not _TA_ANY_RE.search(body):
            return [self._result(url, "typed_array_not_used", "PASS")]

        findings = []

        if _TA_CREDENTIALS_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "typed_array_credentials_exfil", "FAIL",
                detail="Uint8Array containing password/token/credential transmitted via fetch/sendBeacon — binary credential data exfiltrated via TypedArray.",
            ))

        if _TA_BUFFER_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "typed_array_buffer_from_param", "WARN",
                detail="TypedArray initialized from URL parameter — attacker-controlled binary buffer content injection.",
            ))

        if _TA_MEMORY_DUMP_RE.search(body):
            findings.append(self._result(
                url, "typed_array_memory_dump_exfil", "WARN",
                detail="TypedArray memory buffer size measurements transmitted — binary memory layout fingerprinting and exfiltration.",
            ))

        if _TA_WASM_MEMORY_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "typed_array_wasm_memory_exfil", "FAIL",
                detail="WebAssembly.Memory wrapped in Uint8Array and transmitted — WASM linear memory contents exfiltrated to remote endpoint.",
            ))

        return findings or [self._result(url, "typed_array_safe", "PASS")]
