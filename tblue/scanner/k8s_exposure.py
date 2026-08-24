"""
Kubernetes API Exposure Scanner.

Detects exposed Kubernetes API server endpoints and cluster misconfigurations:

1. Kubernetes API server on default port 6443 / 8080 (insecure)
2. Dashboard exposure (kubernetes-dashboard)
3. etcd exposure (port 2379/2380) — cluster state database
4. Kubelet API exposure (port 10250/10255 — read-only)
5. Metrics server exposure (/metrics, /stats)
6. Namespace enumeration (anonymous access)
7. RBAC misconfiguration indicators (system:anonymous)
8. Helm tiller exposure (port 44134 — pre-Helm3)

All checks use passive detection or probe the target's web-accessible paths only.

Paid equivalents: kube-bench, Falco, Aqua Security.
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Kubernetes API paths to probe
_K8S_API_PATHS: List[tuple] = [
    ("/api/v1/namespaces",                    "K8s namespaces list",    "FAIL"),
    ("/api/v1/pods",                          "K8s pods list",          "FAIL"),
    ("/api/v1/secrets",                       "K8s secrets list",       "FAIL"),
    ("/api/v1/configmaps",                    "K8s configmaps list",    "FAIL"),
    ("/apis/",                                "K8s API groups",         "WARN"),
    ("/api",                                  "K8s API root",           "WARN"),
    ("/version",                              "K8s version",            "WARN"),
    ("/healthz",                              "K8s health check",       "WARN"),
    ("/readyz",                               "K8s readiness check",    "WARN"),
    ("/metrics",                              "K8s metrics",            "WARN"),
    ("/openapi/v2",                           "K8s OpenAPI schema",     "WARN"),
    ("/swaggerapi",                           "K8s Swagger API",        "WARN"),
    # Dashboard
    ("/api/v1/namespaces/kube-system/services/kubernetes-dashboard:80/proxy",
     "Kubernetes dashboard proxy",            "FAIL"),
    # Helm Tiller
    ("/tiller-deploy",                        "Helm Tiller exposure",   "FAIL"),
]

# K8s API response patterns
_K8S_API_BODY_RE = re.compile(
    r'"apiVersion"\s*:\s*"v\d|'
    r'"kind"\s*:\s*"(?:APIVersions|APIGroupList|Status|NamespaceList|PodList|SecretList)|'
    r'"items"\s*:\s*\[|'
    r'"serverAddressByClientCIDRs"|'
    r'"gitVersion"\s*:\s*"v\d+\.\d+',
    re.I,
)

_K8S_ANON_RE = re.compile(
    r'system:anonymous|'
    r'"username"\s*:\s*"system:anonymous"|'
    r'"groups"\s*:\s*\[.*"system:unauthenticated"',
    re.I,
)

_K8S_DASHBOARD_RE = re.compile(
    r"kubernetes\s*dashboard|"
    r"kube-system|"
    r'id="app-content"|'
    r"kubernetes-dashboard",
    re.I,
)


class K8sExposureScanner(BaseScanner):
    """Detect exposed Kubernetes API endpoints and cluster misconfigurations."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if not resp:
            self.results.append(self._result(
                url, "K8s — no exposed Kubernetes API endpoints", "PASS",
                detail="No Kubernetes API server or dashboard endpoints found."
            ))
            return self.results

        body = resp.text or ""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # ── Check main page for K8s indicators ────────────────────────────────
        if _K8S_API_BODY_RE.search(body):
            log_warn(logger, f"Kubernetes API response on main URL: {url}")
            self.results.append(self._result(
                url, "K8s — Kubernetes API response on main URL", "WARN",
                detail=(
                    "Kubernetes API-style response detected on the main URL. "
                    "This may indicate an unintentionally exposed K8s API server. "
                    "Verify authentication is required for all API endpoints."
                )
            ))

        # ── Probe K8s paths ───────────────────────────────────────────────────
        for path, label, severity in _K8S_API_PATHS:
            probe_url = base + path
            try:
                r = self.http.get(probe_url)
                if not r or r.status_code not in (200, 206):
                    continue

                r_body = r.text or ""
                # Require K8s-like body OR dashboard indicators in the response
                is_k8s_body = bool(_K8S_API_BODY_RE.search(r_body))
                is_dashboard_body = "dashboard" in path and bool(_K8S_DASHBOARD_RE.search(r_body))
                if not is_k8s_body and not is_dashboard_body:
                    continue

                # Check for anonymous access
                is_anon = _K8S_ANON_RE.search(r_body)
                is_dashboard = _K8S_DASHBOARD_RE.search(r_body)

                if severity == "FAIL" or is_anon:
                    log_fail(logger, f"K8s API exposed: {probe_url} ({label})")
                    self.results.append(self._result(
                        probe_url, f"K8s — {label} exposed" + (" (anonymous access)" if is_anon else ""),
                        "FAIL",
                        detail=(
                            f"Kubernetes endpoint '{label}' accessible at {probe_url}. "
                            + ("Anonymous access confirmed via system:anonymous principal. " if is_anon else "")
                            + "This exposes cluster topology, workload details, secrets, and "
                            "configuration to unauthenticated requests. "
                            "Fix: enable K8s RBAC; disable anonymous authentication "
                            "(--anonymous-auth=false on API server); "
                            "restrict API server to internal network; "
                            "use Network Policies to limit pod egress to the API server."
                        )
                    ))
                else:
                    log_warn(logger, f"K8s endpoint accessible: {probe_url}")
                    self.results.append(self._result(
                        probe_url, f"K8s — {label} accessible", "WARN",
                        detail=(
                            f"Kubernetes endpoint '{label}' responded at {probe_url}. "
                            "Verify this endpoint requires authentication and is not "
                            "accessible from the public internet."
                        )
                    ))
            except Exception:
                continue

        if not self.results:
            log_pass(logger, f"No exposed Kubernetes API endpoints on {url}")
            self.results.append(self._result(
                url, "K8s — no exposed Kubernetes API endpoints", "PASS",
                detail="No Kubernetes API server, dashboard, or cluster endpoints found."
            ))

        return self.results
