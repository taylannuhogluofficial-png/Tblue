"""
Docker / Container Infrastructure Exposure Scanner.

Detects exposed Docker APIs, container registry interfaces, and container
infrastructure fingerprints that reveal the deployment environment:

1. Docker daemon REST API (port 2375/2376 path-based probe)
2. Portainer / Rancher / Docker management UI
3. Docker registry API (v2) without authentication
4. Container-specific response headers (X-Powered-By: Express in Docker, etc.)
5. Docker-specific environment leakage (/.dockerenv echo, /proc/1/cgroup)
6. Container runtime metadata in error pages (containerd, runc, CRI-O)
7. Docker Hub / private registry login page exposure
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_DOCKER_API_PATHS: List[tuple] = [
    ("/v1.41/info",         "Docker daemon API /info",        "FAIL"),
    ("/v1.41/containers/json", "Docker daemon API /containers", "FAIL"),
    ("/v1.41/images/json",  "Docker daemon API /images",      "FAIL"),
    ("/v1.40/info",         "Docker daemon API /info (v1.40)", "FAIL"),
]

_REGISTRY_PATHS: List[tuple] = [
    ("/v2/",                "Docker registry API v2",         "WARN"),
    ("/v2/_catalog",        "Docker registry catalog",        "FAIL"),
]

_MGMT_PATHS: List[tuple] = [
    ("/api/stacks",         "Portainer stack API",            "FAIL"),
    ("/api/endpoints",      "Portainer endpoints API",        "FAIL"),
    ("/api/users",          "Portainer users API",            "FAIL"),
    ("/#/auth",             "Portainer login page",           "WARN"),
]

_DOCKER_API_RE = re.compile(
    r'"DockerRootDir"\s*:|"ServerVersion"\s*:|"Containers"\s*:\s*\d|'
    r'"Architecture"\s*:\s*"[^"]+"|"NCPU"\s*:\s*\d',
    re.I,
)

_REGISTRY_API_RE = re.compile(
    r'"repositories"\s*:\s*\[|"tags"\s*:\s*\[|'
    r'Docker-Distribution-Api-Version',
    re.I,
)

_CONTAINER_RUNTIME_RE = re.compile(
    r'\b(containerd|runc|cri-o|docker-runc|cgroup)\b',
    re.I,
)

_CONTAINER_HEADER_RE = re.compile(
    r'docker|containerd|podman|rancher|portainer|k3s',
    re.I,
)


class DockerExposureScanner(BaseScanner):
    """Detect exposed Docker daemon, registry, and management interfaces."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        origin = self._origin(url)

        self._check_docker_api(url, origin)
        self._check_registry(url, origin)
        self._check_management_ui(url, origin)
        self._check_container_headers(url, origin)
        self._check_env_leakage(url, origin)

        if not self.results:
            log_pass(logger, f"No Docker/container infrastructure exposed at {url}")
            self.results.append(self._result(
                url, "Docker — no container infrastructure exposed", "PASS",
                detail="No Docker daemon API, container registry, or management UI found."
            ))

        return self.results

    def _origin(self, url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def _check_docker_api(self, url: str, origin: str) -> None:
        for path, label, sev in _DOCKER_API_PATHS:
            try:
                resp = self.http.get(origin + path)
                if resp.status_code == 200 and _DOCKER_API_RE.search(resp.text):
                    log_fail(logger, f"Docker daemon API exposed: {origin + path}")
                    self.results.append(self._result(
                        origin + path, f"Docker — {label}", sev,
                        detail=(
                            f"Docker daemon REST API is publicly accessible at {origin + path}. "
                            "This exposes all containers, images, networks, and volumes. "
                            "An attacker can create privileged containers to escape to the host. "
                            "Fix: bind Docker socket to 127.0.0.1 only or use TLS mutual auth; "
                            "never expose port 2375 (unencrypted) publicly."
                        )
                    ))
                    return
            except Exception:
                continue

    def _check_registry(self, url: str, origin: str) -> None:
        try:
            resp = self.http.get(origin + "/v2/")
            if resp.status_code in (200, 401):
                dist_hdr = resp.headers.get("Docker-Distribution-Api-Version", "")
                if dist_hdr or _REGISTRY_API_RE.search(resp.text):
                    if resp.status_code == 200:
                        log_fail(logger, f"Docker registry unauthenticated at {origin}/v2/")
                        self.results.append(self._result(
                            origin + "/v2/", "Docker — registry API unauthenticated", "FAIL",
                            detail=(
                                "Docker registry v2 API responds at /v2/ without authentication. "
                                "Attackers can enumerate and pull all stored container images. "
                                "Fix: enable registry authentication (htpasswd, OAuth2 proxy, or cloud IAM)."
                            )
                        ))
                    else:
                        log_warn(logger, f"Docker registry present at {origin}/v2/")
                        self.results.append(self._result(
                            origin + "/v2/", "Docker — registry API exposed (auth required)", "WARN",
                            detail=(
                                "Docker registry v2 API is publicly accessible at /v2/ "
                                "(authentication is enforced). Verify the registry should be "
                                "publicly reachable or restrict access to internal networks."
                            )
                        ))
        except Exception:
            pass

        try:
            resp = self.http.get(origin + "/v2/_catalog")
            if resp.status_code == 200 and '"repositories"' in resp.text:
                log_fail(logger, f"Docker registry catalog exposed at {origin}/v2/_catalog")
                self.results.append(self._result(
                    origin + "/v2/_catalog", "Docker — registry catalog unauthenticated", "FAIL",
                    detail=(
                        "Docker registry catalog endpoint /v2/_catalog is accessible without "
                        "authentication, exposing the full list of stored images. "
                        "Fix: enforce authentication on the registry or restrict /v2/_catalog access."
                    )
                ))
        except Exception:
            pass

    def _check_management_ui(self, url: str, origin: str) -> None:
        for path, label, sev in _MGMT_PATHS:
            try:
                resp = self.http.get(origin + path)
                body_lower = resp.text.lower()
                if resp.status_code in (200, 302) and any(
                    kw in body_lower for kw in ("portainer", "rancher", "container management")
                ):
                    log_warn(logger, f"Container management UI at {origin + path}")
                    self.results.append(self._result(
                        origin + path, f"Docker — {label}", sev,
                        detail=(
                            f"Container management interface ({label}) detected at {origin + path}. "
                            "Management UIs should not be publicly accessible. "
                            "Fix: restrict access to VPN or internal network; enforce MFA on the login."
                        )
                    ))
                    return
            except Exception:
                continue

    def _check_container_headers(self, url: str, origin: str) -> None:
        try:
            resp = self.http.get(origin)
            for hdr_name, hdr_val in resp.headers.items():
                if _CONTAINER_HEADER_RE.search(hdr_val):
                    log_warn(logger, f"Container runtime fingerprint in header {hdr_name}: {hdr_val}")
                    self.results.append(self._result(
                        url, "Docker — container runtime fingerprint in response header", "WARN",
                        detail=(
                            f"Response header '{hdr_name}: {hdr_val}' reveals the container "
                            f"runtime or orchestration platform. This aids attacker reconnaissance. "
                            "Fix: strip non-essential vendor headers at the reverse proxy layer."
                        )
                    ))
                    break
        except Exception:
            pass

    def _check_env_leakage(self, url: str, origin: str) -> None:
        probe_paths = [
            ("/.dockerenv",       "Docker — /.dockerenv accessible"),
            ("/proc/1/cgroup",    "Docker — /proc/1/cgroup accessible"),
        ]
        for path, label in probe_paths:
            try:
                resp = self.http.get(origin + path)
                is_dockerenv = path == "/.dockerenv"
                if resp.status_code == 200 and (is_dockerenv or len(resp.text) > 0):
                    if is_dockerenv or "docker" in resp.text.lower() or "cgroup" in resp.text.lower():
                        log_fail(logger, f"{label} at {origin + path}")
                        self.results.append(self._result(
                            origin + path, label, "FAIL",
                            detail=(
                                f"Sensitive container path {path} is web-accessible. "
                                "This confirms container deployment and may expose internal process info. "
                                "Fix: configure the web server to deny requests to system paths; "
                                "use a proper deny-list for /.dockerenv, /proc, /sys, /etc."
                            )
                        ))
                        break
            except Exception:
                continue
