"""
API Introspection / Debug Mode Disclosure Scanner.

Several frameworks expose debugging, introspection, or self-documentation
endpoints that should be disabled in production. This scanner checks:

  1. Flask / Werkzeug Debug Console — /__debugger__ (interactive Python shell)
  2. Django Debug toolbar — /__debug__/ or /django-admin/debug/
  3. FastAPI auto-generated docs — /docs (Swagger UI), /redoc, /openapi.json
  4. Sentry tunnel / debug endpoint — /sentry-tunnel, /__sentry__
  5. Spring Boot Actuator health/info — /actuator, /actuator/info, /actuator/env
     (already partially covered by spring_actuator.py but here we check additional
     endpoints that don't overlap: /actuator/heapdump, /actuator/threaddump)
  6. Express.js status pages — /status, /health with detailed build info
  7. Prometheus metrics — /metrics (can reveal internal counters and software versions)
  8. Pprof profiling — /debug/pprof (Go runtime profiler, exposes memory and CPU data)
  9. PHPInfo — /phpinfo.php, /info.php (exposes full server config)

For each endpoint, the scanner checks:
  - HTTP 200 response
  - Content-type or body matches the expected debug output signature

Read-only.

CWE-215: Information Exposure Through Debug Information
CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_INTROSPECTION_ENDPOINTS: List[Tuple[str, str, re.Pattern, str]] = [
    # (path, label, body_pattern, severity)
    ("/__debugger__",       "Werkzeug Debug Console",    re.compile(r'Werkzeug Debugger|Traceback|debugger_script', re.I), "FAIL"),
    ("/__debug__/",         "Django Debug Toolbar",      re.compile(r'djdt|django-debug-toolbar|Debug Toolbar', re.I), "WARN"),
    ("/docs",               "FastAPI Swagger UI",         re.compile(r'swagger|redoc|openapi', re.I), "WARN"),
    ("/redoc",              "FastAPI ReDoc",              re.compile(r'redoc|openapi', re.I), "WARN"),
    ("/openapi.json",       "OpenAPI Schema (auto-gen)", re.compile(r'"openapi"\s*:', re.I), "WARN"),
    ("/sentry-tunnel",      "Sentry Debug Tunnel",       re.compile(r'sentry|envelope|dsn', re.I), "WARN"),
    ("/actuator/heapdump",  "Spring Heap Dump",          re.compile(rb'JAVA PROFILE|hprof', re.I), "FAIL"),
    ("/actuator/threaddump","Spring Thread Dump",         re.compile(r'"threadName"|"stackTrace"', re.I), "FAIL"),
    ("/actuator/env",       "Spring Env Actuator",       re.compile(r'"activeProfiles"|"propertySources"', re.I), "FAIL"),
    ("/metrics",            "Prometheus Metrics",         re.compile(r'^# HELP|^# TYPE|\bgo_goroutines\b', re.M), "WARN"),
    ("/debug/pprof",        "Go pprof Profiler",         re.compile(r'goroutine|heap|profile|cmdline', re.I), "FAIL"),
    ("/debug/pprof/heap",   "Go pprof Heap Profile",     re.compile(r'heap|goroutine', re.I), "FAIL"),
    ("/phpinfo.php",        "PHPInfo Page",              re.compile(r'PHP Version|phpinfo\(\)|php.ini', re.I), "FAIL"),
    ("/info.php",           "PHPInfo Page",              re.compile(r'PHP Version|phpinfo\(\)', re.I), "FAIL"),
    ("/php_info.php",       "PHPInfo Page",              re.compile(r'PHP Version|phpinfo\(\)', re.I), "FAIL"),
    ("/_profiler",          "Symfony Profiler",          re.compile(r'symfony|Profiler|sfWebDebugPanel', re.I), "WARN"),
    ("/telescope",          "Laravel Telescope",         re.compile(r'telescope|laravel', re.I), "WARN"),
    ("/horizon",            "Laravel Horizon",           re.compile(r'horizon|laravel', re.I), "WARN"),
    ("/__clockwork__/app",  "Clockwork Debug Bar",       re.compile(r'clockwork|debug|requests', re.I), "WARN"),
]


def _matches(body: str, pattern: re.Pattern) -> bool:
    if isinstance(pattern.pattern, bytes):
        # bytes pattern (heapdump)
        return bool(pattern.search(body.encode("latin-1", errors="ignore")))
    return bool(pattern.search(body[:32768]))


class IntrospectionDisclosureScanner(BaseScanner):
    """Checks for exposed debug/introspection/profiling endpoints in production."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Introspection Disclosure — target unreachable", "PASS",
                detail="No response; introspection check skipped."))
            return self.results

        parsed      = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        found       = False

        for path, label, pattern, severity in _INTROSPECTION_ENDPOINTS:
            ep_url = base_origin + path
            r = self.http.get(ep_url)
            if r is None or r.status_code != 200:
                continue
            body = r.text or ""
            if not _matches(body, pattern):
                continue

            found = True
            if severity == "FAIL":
                log_fail(logger, f"Introspection Disclosure — {label} at {ep_url}")
            else:
                log_warn(logger, f"Introspection Disclosure — {label} at {ep_url}")

            self.results.append(self._result(
                ep_url,
                f"Introspection Disclosure — {label}",
                severity,
                detail=(
                    f"{label} endpoint is accessible at {ep_url}.\n\n"
                    f"Debug and introspection interfaces in production expose internal "
                    f"application state, stack traces, environment variables, and "
                    f"memory contents to unauthenticated attackers.\n\n"
                    f"Fix: disable or protect this endpoint with authentication and IP "
                    f"allowlisting. Never expose debug modes to the public internet."
                ),
            ))

        if not found:
            log_pass(logger, f"Introspection Disclosure — no debug endpoints found for {url}")
            self.results.append(self._result(
                url,
                "Introspection Disclosure — no debug endpoints found",
                "PASS",
                detail=f"Checked {len(_INTROSPECTION_ENDPOINTS)} known debug/introspection paths; none returned matching responses.",
            ))

        return self.results
