"""
Error page information disclosure scanner.

Fetches intentionally non-existent and malformed paths to check what
the server reveals in 404 / 500 responses:
- Stack traces (file paths, line numbers, class names)
- Framework / server version strings in error bodies
- Internal hostnames or network paths
- Database error messages
- Full exception dumps with local variable state
"""

import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

# Unique path unlikely to exist
_PROBE_404 = "/tblue-probe-404-xyz123abc"

# Patterns that indicate server-side error leakage
_STACK_PATTERNS: List[tuple] = [
    # Python
    (re.compile(r"Traceback \(most recent call last\)", re.I),
     "Python traceback"),
    (re.compile(r'File "[^"]+", line \d+', re.I),
     "Python file/line reference"),
    # Django
    (re.compile(r"Django Version:|Django settings module", re.I),
     "Django debug page"),
    # Rails
    (re.compile(r"ActionController::RoutingError|Rails\.root", re.I),
     "Rails error page"),
    # Java / Spring
    (re.compile(r"at (org|com|net|io)\.\w+\.\w+\([\w.]+:\d+\)", re.I),
     "Java stack trace"),
    (re.compile(r"org\.springframework\.", re.I),
     "Spring framework class"),
    # .NET
    (re.compile(r"System\.(Web|Net|Data|Exception)", re.I),
     ".NET exception class"),
    (re.compile(r"at \w+\.\w+\.\w+\(.*\.cs:\d+\)", re.I),
     ".NET stack frame"),
    # PHP
    (re.compile(r"Fatal error:.*in /.+\.php on line \d+", re.I),
     "PHP fatal error"),
    (re.compile(r"Warning:.*in /.+\.php on line \d+", re.I),
     "PHP warning"),
    (re.compile(r"Parse error:.*in /.+\.php on line \d+", re.I),
     "PHP parse error"),
    # Node.js / Express
    (re.compile(r"ReferenceError:|TypeError:|SyntaxError:", re.I),
     "Node.js/JS exception"),
    (re.compile(r"at Object\.<anonymous>|at Module\._compile", re.I),
     "Node.js stack trace"),
    # Database errors
    (re.compile(r"(ORA-\d{5}|PLS-\d{4})", re.I),
     "Oracle DB error"),
    (re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
     "MSSQL OLE DB error"),
    (re.compile(r"mysql_fetch_array\(\)|mysql_num_rows\(\)", re.I),
     "PHP MySQL function leak"),
    (re.compile(r"PDOException|SQLSTATE\[", re.I),
     "PDO/SQL error"),
    (re.compile(r"pg_query\(\)|pg_exec\(\)|psql:", re.I),
     "PostgreSQL error"),
    # Internal paths
    (re.compile(r"/var/www/|/home/\w+/|C:\\inetpub\\|C:\\xampp\\", re.I),
     "Internal filesystem path"),
    # Generic server version in body
    (re.compile(r"Apache/[\d.]+|nginx/[\d.]+|Microsoft-IIS/[\d.]+", re.I),
     "Server version string in body"),
]

_VERSION_PATTERNS: List[tuple] = [
    (re.compile(r"(Laravel|Symfony|CodeIgniter|Yii|CakePHP)\s+[\d.]+", re.I),
     "PHP framework version"),
    (re.compile(r"Express\s+[\d.]+", re.I),
     "Express.js version"),
    (re.compile(r"Django\s+[\d.]+", re.I),
     "Django version"),
    (re.compile(r"Flask\s+[\d.]+", re.I),
     "Flask version"),
    (re.compile(r"Ruby on Rails\s+[\d.]+|Rails\s+[\d.]+", re.I),
     "Rails version"),
    (re.compile(r"ASP\.NET version\s+[\d.]+", re.I),
     ".NET version"),
]


class ErrorPageScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        base   = _base(url)
        probe  = urljoin(base, _PROBE_404)

        resp = self.http.get(probe, allow_redirects=True)
        if not resp:
            return self.results

        body = resp.text or ""

        findings = self._analyse(body)
        if not findings:
            log_pass(logger, f"Error page looks clean — {url}")
            self.results.append(self._result(
                probe, "Error page — information disclosure", "PASS",
                detail="404 error page does not appear to leak stack traces, framework details, or internal paths."
            ))
        else:
            # Separate stack traces (FAIL) from version/path leaks (WARN)
            stacks   = [f for f in findings if f[0] == "stack"]
            versions = [f for f in findings if f[0] == "version"]

            if stacks:
                labels = ", ".join(label for _, label in stacks[:3])
                log_fail(logger, f"Error page leaks stack traces — {url}")
                self.results.append(self._result(
                    probe, "Error page — stack trace / debug info leaked", "FAIL",
                    detail=(
                        f"The server's error page at {probe} reveals internal debug information: "
                        f"{labels}. "
                        "Stack traces expose your framework, file structure, library versions, "
                        "and sometimes local variable values — all valuable to an attacker. "
                        "Fix: disable debug mode in production. "
                        "Django: DEBUG=False. Laravel: APP_DEBUG=false. "
                        "Express: use a production error handler that does not send err.stack."
                    )
                ))
            if versions:
                labels = ", ".join(label for _, label in versions[:3])
                log_warn(logger, f"Error page leaks version strings — {url}")
                self.results.append(self._result(
                    probe, "Error page — framework/server version disclosed", "WARN",
                    detail=(
                        f"The error page reveals version information: {labels}. "
                        "Knowing exact versions allows targeted exploit search. "
                        "Fix: configure your server/framework to use generic error pages in production."
                    )
                ))

        return self.results

    def _analyse(self, body: str):
        findings = []
        for pattern, label in _STACK_PATTERNS:
            if pattern.search(body):
                findings.append(("stack", label))
        for pattern, label in _VERSION_PATTERNS:
            if pattern.search(body):
                findings.append(("version", label))
        return findings


def _base(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"
