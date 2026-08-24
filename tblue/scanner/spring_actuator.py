"""
Framework Admin Endpoint Exposure Scanner.

Probes for admin/debug/management endpoints exposed by common frameworks
that should never be publicly reachable:

Spring Boot Actuator:
  /actuator/env, /actuator/heapdump, /actuator/mappings, /actuator/beans,
  /actuator/configprops, /actuator/loggers, /actuator/scheduledtasks,
  /actuator/threaddump, /actuator/httptrace, /actuator/metrics

Other frameworks:
  - Django: /django-admin/, /__debug__/ (Django Debug Toolbar)
  - Laravel: /telescope, /horizon
  - Rails: /rails/info/properties, /rails/mailers
  - Express/Node: /debug, /_debug
  - Java EE: /h2-console, /jolokia, /manager (Tomcat)
  - Prometheus/Grafana: /metrics, /prometheus, /grafana
  - Generic: /admin/console, /management, /status, /info, /health/full

All probes are read-only GET requests.

Paid equivalents: Detectify, Qualys WAS, Burp Pro active scan.
"""

from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# (path, label, severity, reason)
_PROBES: List[Tuple[str, str, str, str]] = [
    # ── Spring Boot Actuator (critical paths) ─────────────────────────────
    ("/actuator",              "Spring Actuator root",        "FAIL",
     "Lists all available actuator endpoints — full disclosure of management surface."),
    ("/actuator/env",          "Spring Actuator /env",        "FAIL",
     "Exposes all environment variables and application properties including secrets."),
    ("/actuator/heapdump",     "Spring Actuator /heapdump",   "FAIL",
     "Downloads full JVM heap dump — may contain passwords, tokens, session data."),
    ("/actuator/configprops",  "Spring Actuator /configprops","FAIL",
     "Exposes all Spring configuration properties including database credentials."),
    ("/actuator/beans",        "Spring Actuator /beans",      "WARN",
     "Lists all Spring beans — reveals application structure."),
    ("/actuator/mappings",     "Spring Actuator /mappings",   "WARN",
     "Exposes all HTTP endpoint mappings — full API surface disclosure."),
    ("/actuator/loggers",      "Spring Actuator /loggers",    "WARN",
     "Allows runtime log level changes — can enable verbose logging for exfiltration."),
    ("/actuator/threaddump",   "Spring Actuator /threaddump", "WARN",
     "Thread dump may reveal internal class names, processing states."),
    ("/actuator/httptrace",    "Spring Actuator /httptrace",  "WARN",
     "Recent HTTP requests including headers — may contain auth tokens."),
    ("/actuator/metrics",      "Spring Actuator /metrics",    "WARN",
     "Application metrics — reveals internal performance data."),
    ("/actuator/scheduledtasks","Spring Actuator /scheduledtasks","WARN",
     "Lists all scheduled tasks — reveals background processing jobs."),
    ("/actuator/health",       "Spring Actuator /health",     "WARN",
     "Health status may reveal internal service dependencies."),
    ("/actuator/info",         "Spring Actuator /info",       "WARN",
     "Application info — may include git commit, build details."),
    ("/actuator/shutdown",     "Spring Actuator /shutdown",   "FAIL",
     "Remote shutdown endpoint — allows killing the application."),
    ("/actuator/restart",      "Spring Actuator /restart",    "FAIL",
     "Remote restart endpoint — allows triggering application restart."),

    # ── Java / JVM admin ──────────────────────────────────────────────────
    ("/h2-console",            "H2 Console (in-memory DB)",   "FAIL",
     "H2 database web console — full SQL access to in-memory database."),
    ("/h2-console/",           "H2 Console (trailing slash)", "FAIL",
     "H2 database web console — full SQL access."),
    ("/jolokia",               "Jolokia JMX-HTTP Bridge",     "FAIL",
     "Jolokia exposes all JMX MBeans over HTTP — can execute arbitrary Java code."),
    ("/jolokia/list",          "Jolokia JMX list",            "FAIL",
     "Lists all JMX operations — full management surface."),
    ("/manager/html",          "Tomcat Manager",              "FAIL",
     "Tomcat Manager — allows WAR deployment, application management."),
    ("/manager/status",        "Tomcat Status",               "WARN",
     "Tomcat server status — reveals version and connector details."),
    ("/host-manager/html",     "Tomcat Host Manager",         "FAIL",
     "Tomcat Host Manager — virtual host management."),
    ("/jmx-console",           "JBoss JMX Console",          "FAIL",
     "JBoss JMX Console — remote code execution risk."),
    ("/web-console",           "JBoss Web Console",           "FAIL",
     "JBoss Web Console — server management and deployment."),

    # ── Django ────────────────────────────────────────────────────────────
    ("/django-admin/",         "Django Admin",                "FAIL",
     "Django admin panel — full database access if credentials are weak."),
    ("/admin/",                "Generic Admin Panel",         "WARN",
     "Admin panel accessible — verify authentication is enforced."),
    ("/__debug__/",            "Django Debug Toolbar",        "FAIL",
     "Django Debug Toolbar enabled in production — exposes SQL queries, settings, request data."),

    # ── Laravel ───────────────────────────────────────────────────────────
    ("/telescope",             "Laravel Telescope",           "FAIL",
     "Laravel Telescope debug dashboard — exposes requests, queries, jobs, logs, exceptions."),
    ("/telescope/api/requests","Laravel Telescope API",       "FAIL",
     "Laravel Telescope API — real-time application data."),
    ("/horizon",               "Laravel Horizon",             "WARN",
     "Laravel Horizon queue monitor — reveals job names and payloads."),
    ("/horizon/dashboard",     "Laravel Horizon Dashboard",   "WARN",
     "Laravel Horizon UI — queue management exposed."),

    # ── Rails ─────────────────────────────────────────────────────────────
    ("/rails/info/properties", "Rails Info Properties",       "FAIL",
     "Rails info page — exposes routes, middleware, framework version."),
    ("/rails/info/routes",     "Rails Info Routes",           "FAIL",
     "Rails route information — full URL surface disclosure."),
    ("/rails/mailers",         "Rails Mailer Preview",        "WARN",
     "Rails mailer previews — email template content."),

    # ── Prometheus / Grafana / Metrics ─────────────────────────────────────
    ("/metrics",               "Prometheus Metrics",          "WARN",
     "Prometheus metrics endpoint — application internals, counters, memory."),
    ("/prometheus",            "Prometheus Scrape Endpoint",  "WARN",
     "Prometheus scrape target — detailed application metrics."),
    ("/grafana",               "Grafana Dashboard",           "WARN",
     "Grafana — if not authenticated, full monitoring dashboard access."),

    # ── Express / Node.js ────────────────────────────────────────────────
    ("/_debug",                "Node.js Debug Endpoint",      "FAIL",
     "Node.js debug endpoint — may expose V8 inspector protocol."),
    ("/debug",                 "Generic Debug Endpoint",      "WARN",
     "Debug endpoint accessible — should be restricted to local access."),

    # ── Kubernetes / container ────────────────────────────────────────────
    ("/healthz",               "K8s Healthz Endpoint",        "WARN",
     "Kubernetes health endpoint — confirms K8s deployment, reveals readiness state."),
    ("/readyz",                "K8s Readyz Endpoint",         "WARN",
     "Kubernetes readiness endpoint."),
    ("/metrics/cadvisor",      "cAdvisor Metrics",            "WARN",
     "Container resource metrics — reveals container topology."),
]

# Response body indicators confirming actuator/admin exposure
_SPRING_BODY_RE = __import__("re").compile(
    r'"_links":|"components":|"status":"UP"|actuatorEndpoints|'
    r'"beans":|"contexts":|"activeProfiles"|"properties":|"datasource"',
    __import__("re").I,
)
_H2_BODY_RE = __import__("re").compile(r"H2 Console|Welcome to H2|org\.h2\.", __import__("re").I)
_JOLOKIA_BODY_RE = __import__("re").compile(r'"status":\s*200.*"request":|jolokia', __import__("re").I)


class SpringActuatorScanner(BaseScanner):
    """Detect exposed framework admin and debug endpoints."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        found_critical: List[str] = []
        found_warn: List[str] = []

        for path, label, severity, reason in _PROBES:
            probe_url = base + path
            try:
                r = self.http.get(probe_url)
                if not r:
                    continue

                # Must be 200 or 206 to count as exposed
                if r.status_code not in (200, 206):
                    continue

                rbody = r.text or ""

                # Additional validation to reduce false positives
                confirmed = False
                if "/actuator" in path:
                    confirmed = bool(_SPRING_BODY_RE.search(rbody)) or '"status"' in rbody
                elif path in ("/h2-console", "/h2-console/"):
                    confirmed = bool(_H2_BODY_RE.search(rbody)) or r.status_code == 200
                elif path in ("/jolokia", "/jolokia/list"):
                    confirmed = bool(_JOLOKIA_BODY_RE.search(rbody))
                elif "/telescope" in path:
                    confirmed = "telescope" in rbody.lower() or "laravel" in rbody.lower()
                elif "/__debug__" in path:
                    confirmed = "djdt" in rbody.lower() or "debugtoolbar" in rbody.lower()
                elif "/rails/info" in path:
                    confirmed = "Rails" in rbody or "Ruby" in rbody
                else:
                    confirmed = r.status_code == 200

                if not confirmed:
                    continue

                if severity == "FAIL":
                    found_critical.append((probe_url, label, reason))
                    log_fail(logger, f"Admin endpoint exposed: {probe_url} ({label})")
                else:
                    found_warn.append((probe_url, label, reason))
                    log_warn(logger, f"Management endpoint accessible: {probe_url} ({label})")

            except Exception:
                continue

        for probe_url, label, reason in found_critical:
            self.results.append(self._result(
                probe_url, f"Admin endpoint exposed — {label}", "FAIL",
                detail=(
                    f"{label} is publicly accessible at {probe_url}. "
                    f"{reason} "
                    "Fix: restrict access to management endpoints by IP allowlist or "
                    "remove from production. In Spring Boot, set "
                    "management.server.port to a non-public port and bind to 127.0.0.1. "
                    "Use spring.security to require authentication on /actuator/**."
                )
            ))

        for probe_url, label, reason in found_warn:
            self.results.append(self._result(
                probe_url, f"Management endpoint accessible — {label}", "WARN",
                detail=(
                    f"{label} is accessible at {probe_url}. "
                    f"{reason} "
                    "Verify authentication is enforced and sensitive data is not exposed."
                )
            ))

        if not self.results:
            log_pass(logger, f"No admin/management endpoints exposed on {url}")
            self.results.append(self._result(
                url, "Framework admin endpoints — none exposed", "PASS",
                detail="No Spring Actuator, H2, Jolokia, or framework admin endpoints found."
            ))

        return self.results
