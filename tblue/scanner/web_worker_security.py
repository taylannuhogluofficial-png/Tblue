"""
Web Worker Security Scanner.

Web Workers (Worker, SharedWorker, ServiceWorker) run JavaScript in background
threads. Security issues:

  1. SharedWorker with no origin restriction — SharedWorker instances are
     shared across all same-origin pages. If the worker processes messages
     without validating sender origin or has no authentication, any XSS on
     any same-origin page can communicate with the worker.

  2. Worker importing scripts from untrusted sources — importScripts() in
     a worker fetches external scripts synchronously. Workers importing
     from CDNs without SRI create a supply chain risk.

  3. Worker URL exposed as static JS — worker scripts accessible at
     predictable paths (worker.js, sw.js, /workers/*.js) may contain
     sensitive business logic or credentials.

  4. Service worker with overly broad fetch interception — a SW with
     catch-all fetch handler that forwards requests to a different origin
     can intercept all page requests, including auth tokens.

  5. Worker created from a blob URL with untrusted content — blob: URLs
     for workers constructed from externally-fetched content bypass CSP.

Read-only. Static analysis of served JS.

CWE-346: Origin Validation Error
CWE-693: Protection Mechanism Failure
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_WORKER_PATHS = [
    "/worker.js", "/workers/main.js", "/js/worker.js",
    "/sw.js", "/service-worker.js", "/serviceworker.js",
    "/assets/sw.js", "/static/sw.js",
]

_SHARED_WORKER_RE = re.compile(r'new\s+SharedWorker\s*\(', re.I)
_IMPORT_SCRIPTS_RE = re.compile(r'importScripts\s*\(\s*["\']([^"\']+)["\']', re.I)
_BLOB_WORKER_RE = re.compile(r'new\s+Worker\s*\(\s*URL\.createObjectURL', re.I)
_FETCH_CATCH_ALL_RE = re.compile(
    r'addEventListener\s*\(\s*["\']fetch["\'].*?fetch\s*\(event\.request\)',
    re.I | re.S
)
_ORIGIN_CHECK_RE = re.compile(r'event\.origin\s*===|origin\s*!==\s*|allowedOrigins', re.I)
_SW_FORWARD_RE = re.compile(
    r'fetch\s*\(\s*(?:new\s+Request\s*\()?["\']https?://(?!.*\{)',
    re.I
)


def _scan_worker_body(body: str, url: str) -> List[Dict]:
    findings = []

    # SharedWorker without origin check
    if _SHARED_WORKER_RE.search(body) and not _ORIGIN_CHECK_RE.search(body):
        findings.append({
            "type": "web-worker-shared-worker-no-origin-check",
            "status": "WARN",
            "detail": (
                f"SharedWorker instantiation at {url} with no visible origin check.\n\n"
                f"SharedWorker instances are shared across all tabs of the same origin. "
                f"Without sender origin validation, any XSS payload on any same-origin "
                f"page can communicate with the worker and exfiltrate processed data.\n\n"
                f"Fix: validate postMessage sender origin inside the SharedWorker's "
                f"onmessage handler."
            ),
        })

    # importScripts from cross-origin without integrity
    for match in _IMPORT_SCRIPTS_RE.finditer(body):
        script_url = match.group(1)
        if script_url.startswith("http") and urlparse(script_url).netloc != urlparse(url).netloc:
            findings.append({
                "type": "web-worker-import-scripts-cross-origin",
                "status": "WARN",
                "detail": (
                    f"Worker at {url} calls importScripts({script_url!r}) — "
                    f"cross-origin script import.\n\n"
                    f"importScripts() does not support SRI (integrity attributes). "
                    f"A compromised CDN can serve a malicious script that runs "
                    f"in the worker context with full access to processed data.\n\n"
                    f"Fix: bundle worker scripts locally or pin to a specific "
                    f"content hash via a service worker that intercepts the request."
                ),
            })

    # Blob worker from external content
    if _BLOB_WORKER_RE.search(body):
        findings.append({
            "type": "web-worker-blob-url-construction",
            "status": "WARN",
            "detail": (
                f"Worker at {url} is created from a Blob/ObjectURL.\n\n"
                f"Workers created via URL.createObjectURL() bypass Content Security Policy "
                f"worker-src directives. If the blob content includes externally-fetched "
                f"code, CSP is ineffective.\n\n"
                f"Fix: serve worker scripts from a same-origin URL and rely on CSP "
                f"worker-src to restrict worker origins."
            ),
        })

    return findings


class WebWorkerSecurityScanner(BaseScanner):
    """Checks web worker scripts for SharedWorker origin issues, cross-origin imports, blob workers."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        found = False
        seen_types: set = set()

        endpoints = [url] + [urljoin(base_origin, p) for p in _WORKER_PATHS]

        for ep in endpoints:
            resp = self.http.get(ep)
            if resp is None or resp.status_code not in (200, 206):
                continue
            body = resp.text or ""
            for f in _scan_worker_body(body, ep):
                if f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    found = True
                    log_warn(logger, f"Web Worker Security — {f['type']} at {ep}")
                    self.results.append(self._result(
                        ep, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"Web Worker Security — no issues found for {url}")
            self.results.append(self._result(
                url,
                "Web Worker Security — no risky worker patterns detected",
                "PASS",
                detail="No SharedWorker origin issues, cross-origin importScripts, or blob workers found.",
            ))

        return self.results
