"""
API Error Disclosure Scanner.

API endpoints that return detailed error messages in production disclose:
  - Internal stack traces (Python, Node, Java, Ruby, PHP, Go, .NET)
  - Database query text or ORM error messages
  - Internal hostnames / IP addresses / file paths
  - Framework version strings in error bodies
  - SQL syntax in error text
  - Server-side exception class names

This scanner probes common API endpoints with intentionally malformed
requests (missing required params, invalid types, path beyond depth) and
checks response bodies for telltale disclosure patterns.

PURELY READ-ONLY. It sends benign malformed GET and POST requests — no
payloads designed to execute, only to trigger validation errors.

CWE-209: Generation of Error Message Containing Sensitive Information
CWE-200: Exposure of Sensitive Information
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_API_PROBE_PATHS = [
    "/api/v1/users/99999999",
    "/api/v1/items/not-an-id",
    "/api/v2/search?q[]=evil",
    "/api/v1/",
    "/api/users?limit=not-a-number",
    "/graphql",
    "/api/v1/orders/../../../../etc/passwd",
    "/rest/v1/",
    "/v1/",
]

_STACK_TRACE_PATTERNS = [
    # Python / Django / Flask / FastAPI
    (re.compile(r'Traceback \(most recent call last\)', re.I), "Python stack trace"),
    (re.compile(r'File "[^"]+\.py", line \d+', re.I),         "Python file reference"),
    # Node.js / Express
    (re.compile(r'at Object\.<anonymous>.*node_modules', re.I), "Node.js stack trace"),
    (re.compile(r'Error: Cannot (?:read|set) propert',  re.I), "Node.js TypeError"),
    # Java / Spring
    (re.compile(r'java\.lang\.[A-Z][a-zA-Z]+Exception', re.I), "Java exception class"),
    (re.compile(r'at [a-z]+\.[a-zA-Z]+\.[A-Z][a-zA-Z]+\.',   re.I), "Java stack frame"),
    # Ruby on Rails
    (re.compile(r'ActionController|ActiveRecord::', re.I),     "Ruby on Rails exception"),
    # PHP
    (re.compile(r'Fatal error.*in /[^\s<]+ on line \d+', re.I), "PHP fatal error"),
    (re.compile(r'Warning: .*\(\) expects parameter',    re.I), "PHP warning"),
    # .NET / C#
    (re.compile(r'System\.(?:NullReferenceException|ArgumentException|StackOverflowException)', re.I), ".NET exception"),
    (re.compile(r'at System\.',                         re.I), ".NET stack frame"),
    # Go
    (re.compile(r'goroutine \d+ \[running\]',           re.I), "Go goroutine dump"),
    # SQL errors
    (re.compile(r'(?:syntax error|SQL syntax|mysql_fetch|ORA-\d{4,}|PLS-\d{4,}|SQLSTATE\[)', re.I), "SQL error"),
    (re.compile(r'(?:near|unexpected|unterminated) .*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)', re.I), "SQL fragment in error"),
    # Internal paths / hostnames
    (re.compile(r'/(?:home|var|usr|opt|srv|app)/[a-zA-Z0-9_/]+\.(py|js|rb|php|java|go|cs)', re.I), "Internal file path"),
    (re.compile(r'\b(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b', re.I), "Internal IP/hostname"),
    # Framework version disclosure in error body
    (re.compile(r'(?:Express|Flask|Django|Spring Boot|Rails|Laravel)[/\s]+\d+\.\d+', re.I), "Framework version in error"),
]


def _body_has_disclosure(body: str) -> List[Tuple[str, str]]:
    findings = []
    text = body[:32768]  # first 32KB only
    for pattern, label in _STACK_TRACE_PATTERNS:
        if pattern.search(text):
            findings.append((label, pattern.pattern[:60]))
    return findings


def _probe_endpoint(http, url: str) -> Optional[Dict]:
    """GET probe, then POST probe if GET looks like an API endpoint."""
    # GET
    resp_get = http.get(url)
    if resp_get and resp_get.status_code not in (404, 410, 501, 502, 503, 504):
        body = resp_get.text or ""
        disclosures = _body_has_disclosure(body)
        if disclosures:
            return resp_get.status_code, disclosures

    # POST with malformed JSON
    resp_post = http.post(
        url,
        data='{"id": null, "q": ["nested", "array"]}',
        headers={"Content-Type": "application/json"},
    )
    if resp_post and resp_post.status_code not in (404, 410, 501, 502, 503, 504):
        body = resp_post.text or ""
        disclosures = _body_has_disclosure(body)
        if disclosures:
            return resp_post.status_code, disclosures

    return None


class APIErrorDisclosureScanner(BaseScanner):
    """Checks API endpoints for stack traces, internal paths, and DB errors in responses."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "API Error Disclosure — target unreachable", "PASS",
                detail="No response; API error disclosure check skipped."))
            return self.results

        parsed      = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        found       = False

        for path in _API_PROBE_PATHS:
            ep_url = base_origin + path
            result = _probe_endpoint(self.http, ep_url)
            if result is None:
                continue

            status_code, disclosures = result
            labels = [d[0] for d in disclosures]
            found  = True

            severity = "FAIL" if any(
                kw in l.lower() for l in labels for kw in
                ("stack", "exception", "sql", "traceback", "file path", "internal ip")
            ) else "WARN"

            detail = (
                f"Endpoint {ep_url} (HTTP {status_code}) returned error response "
                f"containing sensitive information:\n\n"
                + "\n".join(f"  - {l}" for l in labels)
                + "\n\nDetailed error messages in production API responses enable "
                "attackers to map internal architecture, identify exploitable "
                "libraries, and target specific vulnerability classes.\n\n"
                "Fix: configure a generic error handler that returns structured "
                "error codes (e.g. {\"error\": \"invalid_request\"}) and logs "
                "full details server-side only."
            )

            if severity == "FAIL":
                log_fail(logger, f"API Error Disclosure — {labels[0]} found at {ep_url}")
            else:
                log_warn(logger, f"API Error Disclosure — {labels[0]} found at {ep_url}")

            self.results.append(self._result(
                ep_url,
                f"API Error Disclosure — {labels[0][:80]}",
                severity,
                detail=detail,
            ))

        if not found:
            log_pass(logger, f"API Error Disclosure — no sensitive error information found for {url}")
            self.results.append(self._result(
                url,
                "API Error Disclosure — no sensitive information in error responses",
                "PASS",
                detail=f"Probed {len(_API_PROBE_PATHS)} API endpoints; no stack traces, "
                       f"SQL errors, internal paths, or exception class names found.",
            ))

        return self.results
