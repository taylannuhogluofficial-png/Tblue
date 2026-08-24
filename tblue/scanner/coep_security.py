"""Cross-Origin Embedder Policy (COEP) security scanner — passive detection of COEP misconfigurations."""
import re
from .base import BaseScanner

_COEP_ANY_RE = re.compile(
    r'(?:Cross-Origin-Embedder-Policy\b|COEP\b|require-corp\b|credentialless\b|'
    r'crossOriginIsolated\b|SharedArrayBuffer\b|Atomics\b)',
    re.I,
)

_COEP_MISSING_SAB_RE = re.compile(
    r'SharedArrayBuffer\b[^;]{0,300}'
    r'(?:postMessage|Worker|transferable)',
    re.I,
)

_COEP_ATOMICS_TIMING_RE = re.compile(
    r'Atomics\.(?:wait|waitAsync|notify)\s*\([^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_COEP_NOT_ISOLATED_RE = re.compile(
    r'crossOriginIsolated\b[^;]{0,100}false',
    re.I,
)

_COEP_BYPASS_CREDENTIALLESS_RE = re.compile(
    r'credentialless\b[^;]{0,200}'
    r'(?:localStorage|sessionStorage|document\.cookie|indexedDB)',
    re.I,
)


class COEPSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "coep_not_used", "PASS")]

        body = resp.text
        headers_str = " ".join(f"{k}: {v}" for k, v in (resp.headers or {}).items())
        combined = body + "\n" + headers_str

        if not _COEP_ANY_RE.search(combined):
            return [self._result(url, "coep_not_used", "PASS")]

        findings = []

        if _COEP_MISSING_SAB_RE.search(body):
            findings.append(self._result(
                url, "coep_shared_array_buffer_usage", "WARN",
                detail="SharedArrayBuffer transferred via postMessage/Worker — requires COEP+COOP for cross-origin isolation.",
            ))

        if _COEP_ATOMICS_TIMING_RE.search(body):
            findings.append(self._result(
                url, "coep_atomics_timing_attack", "FAIL",
                detail="Atomics.wait/notify used in combination with network requests — high-resolution timing oracle for side-channel attacks.",
            ))

        if _COEP_NOT_ISOLATED_RE.search(body):
            findings.append(self._result(
                url, "coep_not_cross_origin_isolated", "WARN",
                detail="crossOriginIsolated is false — SharedArrayBuffer and high-res timers unavailable/unsafe without COOP+COEP.",
            ))

        if _COEP_BYPASS_CREDENTIALLESS_RE.search(body):
            findings.append(self._result(
                url, "coep_credentialless_storage_access", "FAIL",
                detail="credentialless mode embedding accesses localStorage/cookies — storage bypass in COEP-credentialless context.",
            ))

        return findings or [self._result(url, "coep_safe", "PASS")]
