"""WebGPU security scanner — passive detection of GPU timing attacks and fingerprinting."""
import re
from .base import BaseScanner

_GPU_ANY_RE = re.compile(
    r'(?:navigator\.gpu\b|GPUDevice\b|requestAdapter\s*\(\s*\)|GPUBuffer\b|createCommandEncoder\s*\()',
    re.I,
)

_GPU_FINGERPRINT_RE = re.compile(
    r'navigator\.gpu[^;]{0,300}(?:name|vendor|description|limits|features)[^;]{0,200}'
    r'(?:fetch|sendBeacon|analytics|XMLHttpRequest)',
    re.I,
)

_GPU_TIMING_ORACLE_RE = re.compile(
    r'GPUDevice[^;]{0,300}(?:performance\.now|Date\.now)[^;]{0,200}(?:fetch|sendBeacon|analytics)',
    re.I,
)

_GPU_BUFFER_FROM_PARAM_RE = re.compile(
    r'GPUBuffer[^;]{0,200}(?:searchParams|location\.hash)[^;]{0,200}(?:writeBuffer|mapAsync)',
    re.I,
)

_GPU_COMPUTE_EXFIL_RE = re.compile(
    r'(?:computePipeline|dispatchWorkgroups)[^;]{0,300}(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)


class WebGPUSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "webgpu_not_used", "PASS")]

        body = resp.text

        if not _GPU_ANY_RE.search(body):
            return [self._result(url, "webgpu_not_used", "PASS")]

        findings = []

        if _GPU_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "webgpu_adapter_fingerprinting", "FAIL",
                detail="WebGPU adapter name/vendor/limits transmitted to remote — GPU hardware fingerprinting.",
            ))

        if _GPU_TIMING_ORACLE_RE.search(body):
            findings.append(self._result(
                url, "webgpu_timing_oracle", "WARN",
                detail="WebGPU compute timing measured with performance.now and transmitted — side channel timing attack.",
            ))

        if _GPU_BUFFER_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "webgpu_buffer_from_url_param", "FAIL",
                detail="WebGPU buffer data sourced from URL parameters — potential GPU-based SSRF or injection.",
            ))

        if _GPU_COMPUTE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "webgpu_compute_result_exfil", "WARN",
                detail="WebGPU compute pipeline results transmitted to external endpoint — covert compute channel.",
            ))

        return findings or [self._result(url, "webgpu_safe", "PASS")]
