"""
Server Information Disclosure Deep Scanner.

Server banners, error pages, and HTTP headers reveal technology stacks,
exact version numbers, and internal architecture to attackers:

  1. Server header — Apache/2.4.51, nginx/1.21.6, Microsoft-IIS/10.0 with
     exact versions enable targeted CVE lookups.

  2. X-Powered-By — PHP/8.1.0, ASP.NET, Express 4.18.2.

  3. X-AspNet-Version / X-AspNetMvc-Version — .NET runtime version.

  4. X-Generator — CMS or framework (Drupal 9, WordPress 6.2).

  5. Via header — reveals proxy chains and internal hostnames.

  6. X-Backend-Server / X-Served-By / X-Server-Name — internal hostnames.

  7. Verbose error pages — stack traces, file paths, SQL errors embedded
     in HTML body.

Read-only passive.

CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
CWE-209: Generation of Error Message Containing Sensitive Information
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_VERSION_RE = re.compile(r'/(\d+\.\d+(?:\.\d+)?)', re.I)

_DISCLOSURE_HEADERS = [
    ("server", "server-version-disclosure"),
    ("x-powered-by", "x-powered-by-disclosure"),
    ("x-aspnet-version", "aspnet-version-disclosure"),
    ("x-aspnetmvc-version", "aspnet-mvc-version-disclosure"),
    ("x-generator", "x-generator-disclosure"),
    ("x-drupal-cache", "drupal-presence-disclosure"),
    ("x-wordpress-*", "cms-presence-disclosure"),
]

_INTERNAL_HOST_HEADERS = [
    "x-backend-server", "x-served-by", "x-server-name",
    "x-upstream", "x-host", "x-forwarded-server",
]

_STACK_TRACE_RE = re.compile(
    r'(?:Traceback\s*\(most recent|at\s+\w+\.\w+\s*\(.*?\.(?:py|java|cs|rb|php|js):\d+\)|'
    r'SQLException|NullPointerException|Microsoft\.AspNet|'
    r'Warning:\s+(?:include|require|mysql_|pg_)|'
    r'Fatal error:|Parse error:|<b>Fatal error</b>|'
    r'SQLSTATE\[|ORA-\d{5}|syntax error.*SQL)',
    re.I | re.S
)

_FILE_PATH_RE = re.compile(
    r'(?:/var/www/|/home/\w+/|C:\\inetpub\\|/usr/share/|/opt/\w+/)'
    r'[^\s<>"\']{5,80}',
    re.I
)


def _check_version_in_header(name: str, value: str, url: str) -> Optional[Dict]:
    if _VERSION_RE.search(value):
        return {
            "type": f"server-info-{name.lower().replace('-', '_')}-version",
            "status": "WARN",
            "detail": (
                f"HTTP header {name!r} at {url} discloses version information: {value!r}\n\n"
                f"Exact version numbers allow attackers to quickly identify known CVEs "
                f"and unpatched vulnerabilities without active probing.\n\n"
                f"Fix: configure the server to suppress version information from headers. "
                f"In nginx: server_tokens off; in Apache: ServerTokens Prod."
            ),
        }
    return None


def _check_internal_host_headers(headers: dict, url: str) -> List[Dict]:
    findings = []
    for h in _INTERNAL_HOST_HEADERS:
        val = headers.get(h, "")
        if val:
            findings.append({
                "type": "server-info-internal-host-disclosed",
                "status": "WARN",
                "detail": (
                    f"Internal hostname/server disclosed in header {h!r} at {url}: {val!r}\n\n"
                    f"Internal hostnames reveal infrastructure topology and may aid "
                    f"in server-side request forgery (SSRF) target discovery.\n\n"
                    f"Fix: configure your load balancer or CDN to strip backend-revealing headers."
                ),
            })
            break
    return findings


def _check_error_page(body: str, url: str) -> List[Dict]:
    findings = []
    if _STACK_TRACE_RE.search(body[:32768]):
        findings.append({
            "type": "server-info-stack-trace-in-response",
            "status": "WARN",
            "detail": (
                f"Stack trace or verbose error message detected in response body at {url}.\n\n"
                f"Stack traces expose internal code paths, library versions, and sometimes "
                f"credentials or internal URLs.\n\n"
                f"Fix: enable production error handling that shows generic error pages. "
                f"Log full errors server-side only."
            ),
        })
    paths = _FILE_PATH_RE.findall(body[:32768])
    if paths:
        findings.append({
            "type": "server-info-file-path-in-response",
            "status": "WARN",
            "detail": (
                f"Server file paths disclosed in response body at {url}: "
                f"{repr(paths[0])[:80]}\n\n"
                f"Absolute file paths reveal directory structure and installation layout, "
                f"which assists local file inclusion (LFI) and path traversal attacks.\n\n"
                f"Fix: suppress file paths from error messages and application output."
            ),
        })
    return findings


_ERROR_PATHS = ["/nonexistent-tbl9z7x-probe", "/error", "/500"]


class ServerInfoDeepScanner(BaseScanner):
    """Deep check: version headers, internal hosts, stack traces in error pages."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Server Info Deep — target unreachable", "PASS",
                detail="No response; server info deep check skipped."))
            return self.results

        found = False
        seen_types: set = set()
        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}

        # Version-bearing headers
        for h_name, _ in _DISCLOSURE_HEADERS:
            if h_name.endswith("*"):
                continue
            val = headers.get(h_name, "")
            if val:
                f = _check_version_in_header(h_name, val, url)
                if f and f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    found = True
                    log_warn(logger, f"Server Info Deep — {f['type']}")
                    self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        # Internal host headers
        for f in _check_internal_host_headers(headers, url):
            if f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                log_warn(logger, f"Server Info Deep — {f['type']}")
                self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        # Error pages
        for path in _ERROR_PATHS:
            err_resp = self.http.get(base_origin + path)
            if err_resp and err_resp.text:
                for f in _check_error_page(err_resp.text, base_origin + path):
                    if f["type"] not in seen_types:
                        seen_types.add(f["type"])
                        found = True
                        log_warn(logger, f"Server Info Deep — {f['type']}")
                        self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"Server Info Deep — no excessive disclosure for {url}")
            self.results.append(self._result(
                url, "Server Info Deep — no excessive server information disclosure", "PASS",
                detail="No version numbers in headers, internal hostnames, or stack traces found."))

        return self.results
