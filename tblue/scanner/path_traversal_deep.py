"""Path traversal deep — encoded traversal sequences in responses, common vulnerable parameter patterns."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_TRAVERSAL_PARAMS = ["file", "path", "dir", "page", "document", "doc", "template", "include", "load"]

_TRAVERSAL_SEQUENCES = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "..%252F..%252F..%252Fetc%252Fpasswd",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
]

_PASSWD_CONTENT_RE = re.compile(r'root:(?:x|[^:]+):\d+:\d+:', re.M)
_WIN_HOSTS_RE = re.compile(r'127\.0\.0\.1\s+localhost', re.M)
_PHP_SOURCE_RE = re.compile(r'<\?php', re.I)
_UNIX_PATHS_IN_RESPONSE_RE = re.compile(
    r'(?:/etc/passwd|/etc/shadow|/proc/self/environ|/var/www/html)',
    re.I,
)

_NULLABLE_RE = re.compile(r'%00|\\x00|\0')

_FILE_PARAM_URL_RE = re.compile(
    r'[?&](?:file|path|dir|doc|page|template|include|load)=([^&\s]+)',
    re.I,
)

_TRAVERSAL_IN_URL_RE = re.compile(r'(?:\.\./|%2e%2e%2f|%252e%252e|\.\.%2f)', re.I)


def _check_traversal_in_scan_url(url: str) -> list:
    """Check if the target URL itself contains path traversal sequences."""
    findings = []
    if _TRAVERSAL_IN_URL_RE.search(url):
        findings.append({
            "type": "path_traversal_sequence_in_url",
            "status": "WARN",
            "url": url,
            "detail": f"Path traversal sequence detected in URL — may indicate reflected traversal: {url[:80]}",
        })
    return findings


def _check_param_traversal(http, url: str) -> list:
    """Probe file/path parameters with traversal sequences."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for param in _TRAVERSAL_PARAMS[:4]:
        for seq in _TRAVERSAL_SEQUENCES[:3]:
            probe_url = f"{base}?{param}={seq}"
            try:
                resp = http.get(probe_url)
                if resp is None:
                    continue
                body = resp.text or ""
                if _PASSWD_CONTENT_RE.search(body):
                    findings.append({
                        "type": "path_traversal_passwd_read",
                        "status": "FAIL",
                        "url": probe_url,
                        "detail": (f"Path traversal via ?{param}= returns /etc/passwd content — "
                                   f"arbitrary file read confirmed"),
                    })
                    return findings
                if _WIN_HOSTS_RE.search(body):
                    findings.append({
                        "type": "path_traversal_hosts_read",
                        "status": "FAIL",
                        "url": probe_url,
                        "detail": f"Path traversal via ?{param}= returns Windows hosts file content",
                    })
                    return findings
                if _PHP_SOURCE_RE.search(body) and resp.status_code == 200:
                    findings.append({
                        "type": "path_traversal_php_source",
                        "status": "FAIL",
                        "url": probe_url,
                        "detail": f"Path traversal via ?{param}= appears to return PHP source code",
                    })
                    return findings
            except Exception:
                pass
    return findings


def _check_traversal_error_disclosure(http, url: str) -> list:
    """Check if traversal attempts reveal path info in error messages."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    try:
        probe = f"{base}?file=../../../etc/passwd"
        resp = http.get(probe)
        if resp and _UNIX_PATHS_IN_RESPONSE_RE.search(resp.text or ""):
            findings.append({
                "type": "path_traversal_error_path_disclosed",
                "status": "WARN",
                "url": probe,
                "detail": "Unix file path disclosed in error response to traversal probe — reveals filesystem layout",
            })
    except Exception:
        pass
    return findings


class PathTraversalDeepScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []

        for f in _check_traversal_in_scan_url(url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        resp = self.http.get(url)
        if resp is None:
            if not results:
                return [self._result(url, "path_traversal_deep_no_response", "PASS",
                                     detail="No response")]
            return results

        for f in _check_param_traversal(self.http, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            for f in _check_traversal_error_disclosure(self.http, url):
                results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "path_traversal_deep_clean", "PASS",
                                        detail="No path traversal vulnerabilities detected"))
        return results
