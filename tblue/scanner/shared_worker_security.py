"""SharedWorker security scanner — cross-tab data sharing, sensitive state in shared scope."""
import re
from .base import BaseScanner

_SW_ANY_RE = re.compile(
    r'(?:new\s+SharedWorker\s*\(|self\.onconnect\b|SharedWorker\.prototype)',
    re.I
)

# SharedWorker URL derived from URL parameter — attacker loads malicious worker
_SW_URL_FROM_PARAM_RE = re.compile(
    r'new\s+SharedWorker\s*\(\s*[^)]*(?:searchParams|location\.search|getParam)',
    re.I
)

# Sensitive data stored in SharedWorker global scope (shared across all connected tabs)
_SW_SENSITIVE_GLOBAL_RE = re.compile(
    r'(?:self\.onconnect|onconnect\s*=)[^;]{0,500}(?:token|password|apiKey|sessionId|authToken)',
    re.I | re.S
)

# SharedWorker posting sensitive data to all connected ports (broadcast to all tabs)
_SW_BROADCAST_SENSITIVE_RE = re.compile(
    r'ports\b[^;]{0,300}\.postMessage\s*\([^)]*(?:token|password|apiKey|sessionId|cookie)',
    re.I | re.S
)

# SharedWorker making network requests with data from all connected clients
_SW_AGGREGATED_EXFIL_RE = re.compile(
    r'(?:self\.onconnect|onconnect)[^;]{0,500}(?:fetch|XMLHttpRequest|sendBeacon)[^;]{0,200}(?:data|payload|body)',
    re.I | re.S
)

# SharedWorker origin not validated on connect — any origin can connect
_SW_NO_ORIGIN_CHECK_RE = re.compile(
    r'self\.onconnect\s*=[^;]{0,400}(?!.*event\.origin)(?!.*origin\s*===)',
    re.I | re.S
)


class SharedWorkerSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "shared_worker_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _SW_ANY_RE.search(body):
            return [self._result(url, "shared_worker_not_used", "INFO",
                                 detail="SharedWorker API not detected")]

        results = []

        if _SW_URL_FROM_PARAM_RE.search(body):
            results.append(self._result(url, "shared_worker_url_from_param", "FAIL",
                                        detail="SharedWorker URL derived from URL parameter — attacker loads arbitrary worker script via URL manipulation"))

        if _SW_SENSITIVE_GLOBAL_RE.search(body):
            results.append(self._result(url, "shared_worker_sensitive_global_state", "WARN",
                                        detail="Sensitive data (token/apiKey/password) in SharedWorker scope — shared across all tabs, any connected tab can retrieve it"))

        if _SW_BROADCAST_SENSITIVE_RE.search(body):
            results.append(self._result(url, "shared_worker_broadcasts_sensitive_data", "FAIL",
                                        detail="SharedWorker broadcasts sensitive data to all connected ports — all open tabs receive auth tokens or session data"))

        if _SW_AGGREGATED_EXFIL_RE.search(body):
            results.append(self._result(url, "shared_worker_aggregates_and_exfiltrates", "WARN",
                                        detail="SharedWorker aggregates data from multiple clients and transmits to remote endpoint — cross-tab data aggregation exfiltration"))

        if _SW_NO_ORIGIN_CHECK_RE.search(body):
            results.append(self._result(url, "shared_worker_no_origin_check", "WARN",
                                        detail="SharedWorker onconnect handler missing origin validation — cross-origin pages sharing same worker can inject messages"))

        if not results:
            results.append(self._result(url, "shared_worker_found_no_issues", "PASS",
                                        detail="SharedWorker usage appears safe"))

        return results
