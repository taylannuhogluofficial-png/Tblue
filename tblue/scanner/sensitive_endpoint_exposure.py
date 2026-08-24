"""Sensitive endpoint exposure — admin, metrics, debug, internal API paths."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_SENSITIVE_PATHS = [
    # Metrics / monitoring
    ("/metrics",            "prometheus_metrics",    re.compile(r"^# HELP |^# TYPE ", re.M),           "FAIL"),
    ("/actuator",           "spring_actuator_root",  re.compile(r'"_links"\s*:\s*\{', re.I),           "FAIL"),
    ("/actuator/env",       "spring_actuator_env",   re.compile(r'"activeProfiles"|"propertySources"', re.I), "FAIL"),
    ("/actuator/heapdump",  "spring_heapdump",       re.compile(r"JAVA PROFILE|OQL", re.I),            "FAIL"),
    ("/debug/vars",         "go_expvars",            re.compile(r'"goroutine"|"memstats"', re.I),       "FAIL"),
    ("/debug/pprof/",       "go_pprof",              re.compile(r"Types of profiles available|goroutine", re.I), "FAIL"),
    # Admin interfaces
    ("/admin",              "admin_panel",           re.compile(r'(?:<title>|<h1>)[^<]*(?:admin|dashboard)', re.I), "WARN"),
    ("/admin/",             "admin_panel_slash",     re.compile(r'(?:<title>|<h1>)[^<]*(?:admin|dashboard)', re.I), "WARN"),
    ("/wp-admin/",          "wordpress_admin",       re.compile(r"wp-login|WordPress", re.I),           "WARN"),
    ("/_ah/admin",          "gae_admin",             re.compile(r"App Engine|Datastore Viewer", re.I), "WARN"),
    # Health / status
    ("/health",             "health_detailed",       re.compile(r'"status"\s*:\s*"(?:UP|DOWN)".*?"details"', re.I | re.S), "WARN"),
    ("/status.json",        "status_json",           re.compile(r'"version"|"build"', re.I),            "WARN"),
    # Trace / diagnostics
    ("/trace",              "spring_trace",          re.compile(r'"timestamp"|"method"\s*:\s*"', re.I), "WARN"),
    ("/swagger-ui.html",    "swagger_ui",            re.compile(r"swagger-ui|Swagger UI|OpenAPI", re.I), "WARN"),
    ("/api-docs",           "api_docs_json",         re.compile(r'"openapi"|"swagger"', re.I),          "WARN"),
]


def _probe_path(http, origin: str, path: str, label: str,
                pattern: re.Pattern, severity: str) -> dict | None:
    try:
        r = http.get(origin + path)
        if r and r.status_code == 200 and pattern.search(r.text):
            return {
                "type": f"sensitive_endpoint_{label}",
                "status": severity,
                "url": origin + path,
                "detail": f"Sensitive endpoint exposed: {path} ({label})",
            }
    except Exception:
        pass
    return None


class SensitiveEndpointExposureScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "sensitive_endpoint_no_response", "PASS",
                                 detail="No response")]

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for path, label, pattern, severity in _SENSITIVE_PATHS:
            finding = _probe_path(self.http, origin, path, label, pattern, severity)
            if finding:
                results.append(self._result(finding["url"], finding["type"],
                                            finding["status"], detail=finding["detail"]))

        if not results:
            results.append(self._result(url, "sensitive_endpoint_clean", "PASS",
                                        detail="No sensitive endpoints exposed"))
        return results
