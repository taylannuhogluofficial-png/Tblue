"""
Admin panel and debug interface exposure scanner.

Probes common paths for exposed administration interfaces, debug pages,
environment files, and framework-specific diagnostics. Any 200-response
on these paths indicates a misconfiguration that attackers actively exploit.

Strictly read-only: only GET requests, no authentication attempts, no forms.
"""

import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

# (path, label, severity, detail_suffix)
_ADMIN_PROBES: List[tuple] = [
    # Admin panels
    ("/admin",              "Admin panel",              "FAIL",
     "Verify this requires authentication and is not internet-accessible."),
    ("/admin/",             "Admin panel",              "FAIL",
     "Verify this requires authentication and is not internet-accessible."),
    ("/wp-admin/",          "WordPress admin panel",    "FAIL",
     "Restrict with IP allowlisting or a VPN — it's actively brute-forced."),
    ("/administrator/",     "Joomla admin panel",       "FAIL",
     "Restrict with IP allowlisting."),
    ("/manager/html",       "Tomcat manager",           "FAIL",
     "The Tomcat manager should never be internet-accessible."),
    ("/phpmyadmin/",        "phpMyAdmin",               "FAIL",
     "phpMyAdmin provides direct database access. Must be IP-restricted."),
    ("/pma/",               "phpMyAdmin (pma)",         "FAIL",
     "phpMyAdmin provides direct database access. Must be IP-restricted."),
    ("/adminer.php",        "Adminer database UI",      "FAIL",
     "Adminer provides direct database access. Remove or IP-restrict."),
    ("/adminer/",           "Adminer database UI",      "FAIL",
     "Adminer provides direct database access. Remove or IP-restrict."),

    # Debug / profiler endpoints
    ("/_profiler/",         "Symfony profiler",         "FAIL",
     "The Symfony profiler exposes request internals, env vars, and SQL queries."),
    ("/debug/",             "Debug interface",          "WARN",
     "Verify this does not expose stack traces or internal state."),
    ("/debug/default/view", "Yii2 debug module",        "FAIL",
     "Yii2 debug module exposes application internals."),
    ("/telescope",          "Laravel Telescope",        "FAIL",
     "Laravel Telescope exposes all requests, queries, mail, and jobs."),
    ("/horizon",            "Laravel Horizon",          "FAIL",
     "Laravel Horizon exposes queue internals and job payloads."),
    ("/actuator",           "Spring Boot actuator",     "WARN",
     "Spring Boot actuator may expose /actuator/env, /actuator/heapdump, etc."),
    ("/actuator/env",       "Spring Boot env dump",     "FAIL",
     "Exposes all environment variables including credentials."),
    ("/actuator/heapdump",  "Spring Boot heap dump",    "FAIL",
     "A heap dump can contain plaintext credentials and session tokens."),

    # API documentation
    ("/swagger-ui.html",    "Swagger UI",               "WARN",
     "Swagger UI documents and allows live testing of your API."),
    ("/swagger-ui/",        "Swagger UI",               "WARN",
     "Swagger UI documents and allows live testing of your API."),
    ("/api-docs",           "OpenAPI spec",             "WARN",
     "OpenAPI spec enumerates all API endpoints, parameters, and schemas."),
    ("/api-docs/",          "OpenAPI spec",             "WARN",
     "OpenAPI spec enumerates all API endpoints, parameters, and schemas."),
    ("/openapi.json",       "OpenAPI JSON spec",        "WARN",
     "OpenAPI spec enumerates all API endpoints, parameters, and schemas."),
    ("/openapi.yaml",       "OpenAPI YAML spec",        "WARN",
     "OpenAPI spec enumerates all API endpoints, parameters, and schemas."),
    ("/v2/api-docs",        "Swagger v2 spec",          "WARN",
     "Swagger v2 spec enumerates all API endpoints."),
    ("/v3/api-docs",        "Swagger v3 spec",          "WARN",
     "Swagger v3 spec enumerates all API endpoints."),
    ("/graphiql",           "GraphiQL explorer",        "WARN",
     "GraphiQL allows interactive GraphQL query execution against your API."),
    ("/graphql/playground", "GraphQL Playground",       "WARN",
     "GraphQL Playground allows interactive query execution against your API."),
    ("/altair",             "Altair GraphQL client",    "WARN",
     "Altair client allows interactive GraphQL query execution."),

    # Server status / monitoring
    ("/server-status",      "Apache server-status",     "FAIL",
     "Apache server-status exposes request logs, client IPs, and server internals."),
    ("/server-info",        "Apache server-info",       "FAIL",
     "Apache server-info exposes module configuration."),
    ("/nginx_status",       "nginx status page",        "WARN",
     "nginx status exposes active connections and request counts."),
    ("/status",             "Status page",              "WARN",
     "Verify this does not expose internal service state or credentials."),

    # Sensitive config / backup files
    ("/.env",               ".env file",                "FAIL",
     "The .env file commonly contains database credentials, API keys, and secrets."),
    ("/.env.local",         ".env.local file",          "FAIL",
     "Contains application secrets. Must not be publicly accessible."),
    ("/.env.production",    ".env.production file",     "FAIL",
     "Contains production secrets. Must not be publicly accessible."),
    ("/config.php",         "config.php",               "WARN",
     "May contain database credentials."),
    ("/configuration.php",  "configuration.php",        "WARN",
     "May contain database credentials (common in Joomla)."),
    ("/wp-config.php.bak",  "WordPress config backup",  "FAIL",
     "Backup of wp-config.php which contains DB credentials."),
    ("/web.config.bak",     "web.config backup",        "FAIL",
     "Backup of web.config which may contain connection strings."),

    # Cloud/container metadata (via SSRF checks)
    ("/latest/meta-data/",  "AWS instance metadata",    "FAIL",
     "The AWS EC2 metadata endpoint should never be reachable from the internet."),
]

# Patterns that indicate the path returned real content (not a generic 200 from SPA routing)
_FALSE_POSITIVE_BODY_PATTERNS = [
    re.compile(r"<title>.*?(404|not found|error).*?</title>", re.I | re.S),
    re.compile(r'"status"\s*:\s*"?404"?', re.I),
]

# Minimum response body size to be credible (avoids flagging empty 200s from SPA catch-alls)
_MIN_BODY_LEN = 64


class AdminExposureScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        findings = []
        for path, label, severity, fix in _ADMIN_PROBES:
            probe_url = base + path
            finding   = self._probe(probe_url, path, label, severity, fix, url)
            if finding:
                findings.append(finding)

        self.results.extend(findings)
        if not findings:
            log_pass(logger, "No exposed admin/debug paths found")
            self.results.append(self._result(url,
                "Admin exposure — no sensitive paths exposed",
                "PASS",
                detail=f"Checked {len(_ADMIN_PROBES)} common admin/debug/config paths — none returned a 200 response."))

        return self.results

    def _probe(self, probe_url: str, path: str, label: str,
               severity: str, fix: str, origin_url: str) -> Optional[Dict[str, Any]]:
        try:
            resp = self.http.get(probe_url, allow_redirects=True)
            if not resp or resp.status_code != 200:
                return None
            body = resp.text or ""
            # Guard against SPA catch-all routes returning 200 for everything
            if len(body) < _MIN_BODY_LEN:
                return None
            for pat in _FALSE_POSITIVE_BODY_PATTERNS:
                if pat.search(body):
                    return None
            if severity == "FAIL":
                log_fail(logger, f"Exposed: {label} at {probe_url}")
            else:
                log_warn(logger, f"Accessible: {label} at {probe_url}")
            return self._result(
                probe_url,
                f"Admin exposure — {label} accessible ({path})",
                severity,
                detail=(
                    f"{label} returned HTTP 200 at {probe_url}. "
                    f"{fix}"
                )
            )
        except Exception:
            return None
