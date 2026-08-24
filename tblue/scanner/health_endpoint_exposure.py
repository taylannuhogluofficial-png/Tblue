"""
Health / Readiness Endpoint Exposure Scanner.

Detects operational endpoints that leak infrastructure information when
publicly accessible without authentication:

1. /health, /healthz, /ready, /readyz, /liveness — Kubernetes probe paths
2. /metrics — Prometheus metrics (reveals service topology and performance data)
3. /status, /ping, /alive — common framework health paths
4. /info — Spring Boot info endpoint
5. Debug/profiling: /debug/pprof (Go), /debug/vars (expvar)
6. Node.js cluster status, worker metrics

Risk: These endpoints reveal internal service names, dependency health,
build versions, database connection counts, and operational metrics —
a full inventory for attackers planning lateral movement.
"""

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_HEALTH_PATHS: List[Tuple[str, str, str]] = [
    ("/healthz",            "Kubernetes /healthz",          "WARN"),
    ("/readyz",             "Kubernetes /readyz",           "WARN"),
    ("/livez",              "Kubernetes /livez",            "WARN"),
    ("/health",             "Health check endpoint",        "WARN"),
    ("/health/live",        "Health live check",            "WARN"),
    ("/health/ready",       "Health ready check",           "WARN"),
    ("/ready",              "Readiness probe",              "WARN"),
    ("/alive",              "Liveness probe",               "WARN"),
    ("/ping",               "Ping endpoint",                "WARN"),
    ("/status",             "Status endpoint",              "WARN"),
    ("/metrics",            "Prometheus metrics",           "FAIL"),
    ("/actuator/health",    "Spring Boot health",           "WARN"),
    ("/actuator/info",      "Spring Boot info",             "WARN"),
    ("/actuator/metrics",   "Spring Boot metrics",          "FAIL"),
    ("/info",               "Framework info endpoint",      "WARN"),
    ("/debug/pprof",        "Go pprof profiler",            "FAIL"),
    ("/debug/vars",         "Go expvar debug endpoint",     "FAIL"),
    ("/debug",              "Debug endpoint",               "FAIL"),
    ("/_cat/health",        "Elasticsearch cluster health", "WARN"),
    ("/_cluster/health",    "Elasticsearch cluster health", "WARN"),
    ("/node/stats",         "Node.js cluster stats",        "WARN"),
]

_PROMETHEUS_RE = re.compile(
    r'(?:^|\n)#\s+(?:HELP|TYPE)\s+\w',
    re.M,
)

_INTERNAL_HOST_RE = re.compile(
    r'(?:host|address|endpoint|database|redis|mongo|mysql|postgres|kafka|rabbitmq|service)\s*[:=]\s*["\']?[a-z0-9\-_.]+["\']?',
    re.I,
)

_VERSION_RE = re.compile(r'"version"\s*:\s*"[^"]+"', re.I)

_HEALTH_STATUS_RE = re.compile(r'"status"\s*:\s*"(?:UP|DOWN|HEALTHY|OK|alive|ready)"', re.I)

_DB_COMPONENT_RE = re.compile(
    r'"(?:db|database|redis|mongo|mysql|postgres|elasticsearch|kafka|rabbitmq|amqp)"\s*:\s*\{',
    re.I,
)


class HealthEndpointExposureScanner(BaseScanner):
    """Detect exposed health, readiness, and metrics endpoints."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        for path, label, sev in _HEALTH_PATHS:
            try:
                resp = self.http.get(origin + path)
                if resp is None or resp.status_code not in (200, 204):
                    continue
                body = resp.text

                is_prometheus   = _PROMETHEUS_RE.search(body)
                has_internal    = _INTERNAL_HOST_RE.search(body)
                has_version     = _VERSION_RE.search(body)
                has_db_keys     = _DB_COMPONENT_RE.search(body)
                is_health_json  = _HEALTH_STATUS_RE.search(body) or (
                    resp.headers.get("content-type", "").startswith("application/json")
                    and ("status" in body.lower() or "health" in body.lower())
                )

                if not (is_prometheus or has_internal or has_version or has_db_keys or is_health_json):
                    continue

                detail_parts = []
                if is_prometheus:
                    detail_parts.append("Prometheus metric names and values exposed")
                if has_internal:
                    detail_parts.append("internal service hostnames/addresses revealed")
                if has_version:
                    detail_parts.append("application/dependency versions disclosed")
                if has_db_keys:
                    detail_parts.append("database component health status exposed")

                detail = (
                    f"{label} at {origin + path} is publicly accessible without authentication. "
                    f"Findings: {'; '.join(detail_parts) or 'health status data exposed'}. "
                    "Health endpoints reveal service topology, dependency names, and performance "
                    "metrics that aid attacker reconnaissance and lateral movement planning. "
                    "Fix: require authentication for all health endpoints except a minimal "
                    "/healthz that returns only 200/503 with no body; restrict /metrics to "
                    "internal monitoring networks; use Kubernetes NetworkPolicies to limit probe access."
                )

                effective_sev = "FAIL" if (is_prometheus or has_internal or has_db_keys) else sev
                if effective_sev == "FAIL":
                    log_fail(logger, f"{label} exposed at {origin + path}")
                else:
                    log_warn(logger, f"{label} exposed at {origin + path}")

                self.results.append(self._result(
                    origin + path,
                    f"Health endpoint — {label} publicly accessible",
                    effective_sev,
                    detail=detail,
                ))

                if len(self.results) >= 5:
                    break
            except Exception:
                continue

        if not self.results:
            log_pass(logger, f"No exposed health/metrics endpoints at {url}")
            self.results.append(self._result(
                url, "Health endpoint — no exposed health or metrics endpoints", "PASS",
                detail="No health, readiness, or metrics endpoints found accessible without authentication."
            ))

        return self.results
