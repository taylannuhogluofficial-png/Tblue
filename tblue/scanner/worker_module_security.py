"""Worker Module security scanner — passive detection of module worker injection attacks."""
import re
from .base import BaseScanner

_WM_ANY_RE = re.compile(
    r'(?:new\s+Worker\s*\(|new\s+SharedWorker\s*\(|'
    r'importScripts\s*\(|workerModule\b|worker\.postMessage\s*\(|worker\.type\s*=)',
    re.I,
)

_WM_URL_FROM_PARAM_RE = re.compile(
    r'new\s+(?:Worker|SharedWorker)\s*\([^)]*(?:searchParams|location\.hash|location\.href|decodeURIComponent)[^)]*\)',
    re.I,
)

_WM_EXTERNAL_MODULE_RE = re.compile(
    r'new\s+(?:Worker|SharedWorker)\s*\(\s*["\']https?://(?!(?:localhost|127\.0\.0\.1))',
    re.I,
)

_WM_IMPORT_SCRIPTS_FROM_PARAM_RE = re.compile(
    r'importScripts\s*\([^)]*(?:searchParams|location\.hash|location\.href|decodeURIComponent)[^)]*\)',
    re.I,
)

_WM_SENSITIVE_WORKER_POSTMSG_RE = re.compile(
    r'worker\.postMessage\s*\([^)]*(?:token|password|auth|secret|cookie)[^)]*\)',
    re.I,
)


class WorkerModuleSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "worker_module_not_used", "PASS")]

        body = resp.text

        if not _WM_ANY_RE.search(body):
            return [self._result(url, "worker_module_not_used", "PASS")]

        findings = []

        if _WM_URL_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "worker_module_url_from_param", "FAIL",
                detail="Worker/SharedWorker URL sourced from URL parameter — attacker-controlled worker code execution.",
            ))

        if _WM_EXTERNAL_MODULE_RE.search(body):
            findings.append(self._result(
                url, "worker_module_external_url", "WARN",
                detail="Worker loaded from external domain — third-party code running in worker context.",
            ))

        if _WM_IMPORT_SCRIPTS_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "worker_importscripts_from_param", "FAIL",
                detail="importScripts() URL sourced from URL parameter — attacker-controlled script import into worker context.",
            ))

        if _WM_SENSITIVE_WORKER_POSTMSG_RE.search(body):
            findings.append(self._result(
                url, "worker_postmessage_sensitive_data", "FAIL",
                detail="worker.postMessage() sends credentials/tokens to worker — sensitive data transmitted to worker context.",
            ))

        return findings or [self._result(url, "worker_module_safe", "PASS")]
