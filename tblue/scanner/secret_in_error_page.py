"""Secret in error page — stack traces, internal paths, DB strings, API keys in 404/500 responses."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_STACK_TRACE_RE = re.compile(
    r'(?:Traceback \(most recent call last\)|at\s+\w+\.\w+\([^)]*\.(?:py|java|rb|go|js|ts|cs|php):\d+\)|'
    r'stack trace:|Exception in thread|#\d+\s+0x[0-9a-f]+ in)',
    re.I,
)
_DB_CONNECTION_RE = re.compile(
    r'(?:mysql|postgresql|postgres|mongodb|redis|sqlite|mssql|jdbc)://[^\s"\'<>]+',
    re.I,
)
_INTERNAL_PATH_RE = re.compile(
    r'(?:/home/[a-z_][a-z0-9_]*/|/var/www/|/usr/local/|/opt/[a-zA-Z]|C:\\Users\\|D:\\inetpub\\|'
    r'/app/|/srv/|/data/|/code/)[a-zA-Z0-9_/\\.]{5,}',
    re.I,
)
_API_KEY_IN_ERROR_RE = re.compile(
    r'(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|client[_\-]?secret)\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})',
    re.I,
)
_EMAIL_IN_ERROR_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

_ERROR_PROBE_PATHS = [
    "/nonexistent-tbl9z7x-error-probe",
    "/error",
    "/?cause=error",
    "/throw",
    "/500",
]


def _scan_body_for_secrets(body: str, url: str) -> list:
    findings = []
    if _STACK_TRACE_RE.search(body):
        findings.append({
            "type": "error_page_stack_trace",
            "status": "FAIL",
            "url": url,
            "detail": "Server-side stack trace detected in response — reveals code paths and file structure",
        })
    m = _DB_CONNECTION_RE.search(body)
    if m:
        findings.append({
            "type": "error_page_db_connection_string",
            "status": "FAIL",
            "url": url,
            "detail": f"Database connection string exposed in error page: {m.group(0)[:60]}",
        })
    m = _INTERNAL_PATH_RE.search(body)
    if m:
        findings.append({
            "type": "error_page_internal_path",
            "status": "WARN",
            "url": url,
            "detail": f"Internal filesystem path in error page: {m.group(0)[:80]}",
        })
    m = _API_KEY_IN_ERROR_RE.search(body)
    if m:
        findings.append({
            "type": "error_page_api_key_leak",
            "status": "FAIL",
            "url": url,
            "detail": f"API key or secret visible in error page: {m.group(0)[:60]}",
        })
    return findings


class SecretInErrorPageScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "error_page_no_response", "PASS",
                                 detail="No response")]

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        probed = False
        for path in _ERROR_PROBE_PATHS:
            r = self.http.get(origin + path)
            if r is None:
                continue
            probed = True
            if r.status_code in (404, 500, 400, 422, 503):
                for f in _scan_body_for_secrets(r.text, origin + path):
                    results.append(self._result(f["url"], f["type"], f["status"],
                                                detail=f["detail"]))

        if not probed:
            return [self._result(url, "error_page_no_response", "PASS",
                                 detail="No error pages responded")]

        if not results:
            results.append(self._result(url, "error_page_clean", "PASS",
                                        detail="No secrets found in error pages"))
        return results
