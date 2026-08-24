"""Actuator Endpoint Exposure scanner — passive detection of exposed diagnostic/health endpoints."""
import re
from .base import BaseScanner

_AEE_ANY_RE = re.compile(
    r'(?:/actuator|/health|/metrics|/info|/env|/heapdump|'
    r'/_debug|/__debug__|/prometheus|/jolokia|'
    r'spring\.application|management\.endpoints)',
    re.I,
)

_AEE_SPRING_ACTUATOR_RE = re.compile(
    r'(?:"_links"\s*:\s*\{[^}]{0,500}"actuator"|'
    r'"status"\s*:\s*"(?:UP|DOWN|OUT_OF_SERVICE|UNKNOWN)"\s*,\s*"components"|'
    r'/actuator/(?:env|heapdump|threaddump|loggers|mappings|beans))',
    re.I,
)

_AEE_ENV_DISCLOSURE_RE = re.compile(
    r'(?:"(?:systemProperties|systemEnvironment|applicationConfig)"\s*:\s*\{|'
    r'"name"\s*:\s*"(?:systemProperties|systemEnvironment|applicationConfig)")',
    re.I,
)

_AEE_HEAP_DUMP_RE = re.compile(
    r'(?:/actuator/heapdump|heapdump\?live|java\.lang\.OutOfMemoryError)',
    re.I,
)

_AEE_PROMETHEUS_RE = re.compile(
    r'(?:# HELP\s+\w+|# TYPE\s+\w+\s+(?:counter|gauge|histogram|summary)|'
    r'http_requests_total\{)',
    re.I,
)

_AEE_JOLOKIA_RE = re.compile(
    r'(?:/jolokia/|"type"\s*:\s*"(?:read|write|exec|search|list|version)"\s*,\s*"mbean")',
    re.I,
)

_AEE_HEALTH_DETAIL_RE = re.compile(
    r'"db"\s*:\s*\{"status"\s*:\s*"|'
    r'"diskSpace"\s*:\s*\{"status"|'
    r'"redis"\s*:\s*\{"status"|'
    r'"components"\s*:\s*\{[^}]{0,500}"db"',
    re.I,
)


class ActuatorEndpointExposureScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "actuator_endpoint_not_used", "PASS")]

        body = resp.text
        headers_str = ' '.join(f'{k}: {v}' for k, v in resp.headers.items())

        if not _AEE_ANY_RE.search(body) and not _AEE_ANY_RE.search(url):
            return [self._result(url, "actuator_endpoint_not_used", "PASS")]

        findings = []

        if _AEE_SPRING_ACTUATOR_RE.search(body):
            findings.append(self._result(
                url, "actuator_spring_actuator_exposed", "FAIL",
                detail="Spring Boot Actuator endpoint response detected (_links, status: UP, /actuator/env) — Actuator endpoints expose JVM state, environment variables, application config, thread dumps, and heap dumps; critical data for attackers pivoting from reconnaissance to exploitation.",
            ))

        if _AEE_ENV_DISCLOSURE_RE.search(body):
            findings.append(self._result(
                url, "actuator_env_disclosure", "FAIL",
                detail="Spring Actuator /env response with systemProperties/systemEnvironment — environment variables including database passwords, API keys, cloud credentials, and JVM arguments returned in plaintext.",
            ))

        if _AEE_HEAP_DUMP_RE.search(body) or _AEE_HEAP_DUMP_RE.search(url):
            findings.append(self._result(
                url, "actuator_heapdump_accessible", "FAIL",
                detail="JVM heap dump endpoint (/actuator/heapdump) accessible — heap dumps contain full JVM memory including all in-memory secrets, session tokens, database connection strings, and decrypted credentials at the moment of capture.",
            ))

        if _AEE_PROMETHEUS_RE.search(body):
            findings.append(self._result(
                url, "actuator_prometheus_exposed", "WARN",
                detail="Prometheus metrics endpoint exposed — reveals application internals: request rates, error rates, latency percentiles, JVM memory usage, database connection pool state, and custom business metrics without authentication.",
            ))

        if _AEE_JOLOKIA_RE.search(body) or _AEE_JOLOKIA_RE.search(url):
            findings.append(self._result(
                url, "actuator_jolokia_exposed", "FAIL",
                detail="Jolokia JMX-over-HTTP endpoint detected — Jolokia exposes all JMX MBeans via REST; attackers can read/write MBean attributes and invoke operations including classloading, thread management, and JVM shutdown.",
            ))

        if _AEE_HEALTH_DETAIL_RE.search(body):
            findings.append(self._result(
                url, "actuator_health_detail_exposed", "WARN",
                detail="Detailed health endpoint response includes component status (db, redis, diskSpace) — reveals internal infrastructure topology: database type, Redis presence, disk usage; aids attacker reconnaissance of backend services.",
            ))

        return findings or [self._result(url, "actuator_endpoint_safe", "PASS")]
