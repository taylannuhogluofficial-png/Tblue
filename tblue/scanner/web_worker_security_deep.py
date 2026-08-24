"""Web Worker security deep — SharedArrayBuffer without COOP/COEP, Atomics.wait abuse, worker data exposure."""
import re
from .base import BaseScanner

_SHARED_ARRAY_BUFFER_RE = re.compile(r'\bSharedArrayBuffer\b', re.I)
_ATOMICS_RE = re.compile(r'\bAtomic[s]?\b', re.I)
_WORKER_NEW_RE = re.compile(r'new\s+(?:Worker|SharedWorker)\s*\(', re.I)
_IMPORTSCRIPTS_RE = re.compile(r'importScripts\s*\(', re.I)
_EXTERNAL_IMPORTSCRIPTS_RE = re.compile(
    r'importScripts\s*\(\s*["\']https?://', re.I
)
_POSTMESSAGE_WILDCARD_RE = re.compile(
    r'\.postMessage\s*\([^,)]+,\s*["\'][*]["\']',
    re.I,
)
_WORKER_URL_FROM_PARAM_RE = re.compile(
    r'new\s+Worker\s*\(\s*(?:location\.|window\.|document\.|'
    r'(?:get)?[Pp]aram|searchParams|URLSearchParams)',
    re.I,
)
_BLOB_WORKER_WITH_EVAL_RE = re.compile(
    r'new\s+Blob\s*\([^)]*eval|new\s+Worker.*blob.*eval',
    re.I,
)

_COOP_RE = re.compile(r'cross-origin-opener-policy', re.I)
_COEP_RE = re.compile(r'cross-origin-embedder-policy', re.I)


def _get_header(headers, name: str) -> str:
    if hasattr(headers, "get"):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    if isinstance(headers, dict):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    return ""


class WebWorkerSecurityDeepScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "web_worker_deep_no_response", "PASS",
                                 detail="No response")]

        body = resp.text or ""
        headers = resp.headers

        coop = _get_header(headers, "cross-origin-opener-policy")
        coep = _get_header(headers, "cross-origin-embedder-policy")

        uses_sab = bool(_SHARED_ARRAY_BUFFER_RE.search(body))
        uses_atomics = bool(_ATOMICS_RE.search(body))

        if uses_sab or uses_atomics:
            if not coop or not coep:
                missing = []
                if not coop:
                    missing.append("Cross-Origin-Opener-Policy")
                if not coep:
                    missing.append("Cross-Origin-Embedder-Policy")
                results.append(self._result(
                    url, "web_worker_sab_without_isolation", "FAIL",
                    detail=(f"SharedArrayBuffer/Atomics used but {', '.join(missing)} header(s) missing — "
                            f"SAB requires cross-origin isolation (COOP: same-origin + COEP: require-corp) "
                            f"to prevent Spectre-class timing attacks"),
                ))

        if _EXTERNAL_IMPORTSCRIPTS_RE.search(body):
            results.append(self._result(
                url, "web_worker_external_importscripts", "WARN",
                detail="Web Worker imports external script via importScripts() from absolute URL — "
                       "external script compromise would execute in worker context with full data access",
            ))

        if _POSTMESSAGE_WILDCARD_RE.search(body):
            results.append(self._result(
                url, "web_worker_postmessage_wildcard", "WARN",
                detail="postMessage() with '*' targetOrigin detected — "
                       "messages with sensitive data sent to any window regardless of origin",
            ))

        if _WORKER_URL_FROM_PARAM_RE.search(body):
            results.append(self._result(
                url, "web_worker_url_from_param", "FAIL",
                detail="Worker URL appears to be sourced from URL parameter — "
                       "attacker may control worker script URL, enabling arbitrary code execution in worker",
            ))

        if _BLOB_WORKER_WITH_EVAL_RE.search(body):
            results.append(self._result(
                url, "web_worker_blob_eval", "WARN",
                detail="Blob URL worker with eval() detected — dynamic code execution in worker context bypasses CSP",
            ))

        uses_workers = bool(_WORKER_NEW_RE.search(body))

        if not results:
            if uses_workers:
                results.append(self._result(
                    url, "web_worker_in_use_no_issues", "PASS",
                    detail="Web Workers detected but no security issues identified",
                ))
            else:
                results.append(self._result(
                    url, "web_worker_not_used", "PASS",
                    detail="No Web Worker usage detected on this page",
                ))
        return results
