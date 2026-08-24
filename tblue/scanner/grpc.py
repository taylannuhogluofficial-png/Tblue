"""
gRPC / Protobuf Endpoint Detection Scanner.

gRPC is increasingly used in microservice architectures. Exposed gRPC endpoints
without proper authentication or TLS are high-risk:

1. gRPC reflection API — exposes full service/method definitions (like WSDL for SOAP)
2. gRPC-Web endpoints — gRPC over HTTP/1.1 for browser clients
3. Content-Type: application/grpc in responses
4. Known gRPC admin/health paths (/grpc.health.v1.Health/Check)
5. gRPC-Gateway REST transcoding exposure
6. Missing TLS on gRPC endpoints

Paid equivalents: Burp Suite Pro with gRPC extension, Postman.
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_GRPC_PATHS = [
    # gRPC reflection
    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
    "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
    # Health check
    "/grpc.health.v1.Health/Check",
    "/grpc.health.v1.Health/Watch",
    # gRPC-Web common paths
    "/grpc",
    "/grpc-web",
    "/api/grpc",
    "/rpc",
    # Common gRPC-Gateway patterns
    "/v1/grpc",
    "/internal/grpc",
]

_GRPC_CONTENT_TYPE_RE = re.compile(
    r"application/grpc(?:-web)?(?:\+(?:proto|json))?",
    re.I,
)

_GRPC_BODY_RE = re.compile(
    r"grpc-status|grpc-message|application/grpc|"
    r"protobuf|proto3|google\.protobuf|"
    r'"@type"\s*:\s*"type\.googleapis\.com|'
    r"grpc\.reflection\.",
    re.I,
)

_GRPC_HEADER_RE = re.compile(
    r"grpc-status|grpc-message|grpc-encoding|grpc-accept-encoding|"
    r"content-type.*application/grpc",
    re.I,
)


class GRPCScanner(BaseScanner):
    """Detect exposed gRPC endpoints and reflection services."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        # ── Check main page headers ────────────────────────────────────────────
        resp = self.http.get(url)
        if resp:
            headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
            content_type = resp.headers.get("content-type", "")

            if _GRPC_CONTENT_TYPE_RE.search(content_type):
                log_warn(logger, f"gRPC content type on main URL: {content_type}")
                self.results.append(self._result(
                    url, "gRPC — gRPC content type on main endpoint", "WARN",
                    detail=(
                        f"Main URL returns Content-Type: {content_type}. "
                        "gRPC endpoints should require mTLS or JWT authentication. "
                        "Verify authentication and authorization are enforced."
                    )
                ))

            if _GRPC_HEADER_RE.search(headers_str):
                log_warn(logger, f"gRPC protocol headers detected on {url}")
                self.results.append(self._result(
                    url, "gRPC — gRPC protocol headers detected", "WARN",
                    detail=(
                        "gRPC-specific headers (grpc-status, grpc-message) found. "
                        "Confirm authentication is required for all gRPC methods."
                    )
                ))

        # ── Probe gRPC paths ──────────────────────────────────────────────────
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        found_reflection = False
        found_health = False
        found_grpc: List[str] = []

        for path in _GRPC_PATHS:
            probe_url = base + path
            try:
                r = self.http.get(probe_url, headers={"Content-Type": "application/grpc"})
                if not r:
                    continue

                body = r.text or ""
                resp_headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())

                is_grpc = (
                    _GRPC_CONTENT_TYPE_RE.search(r.headers.get("content-type", "")) or
                    _GRPC_BODY_RE.search(body) or
                    _GRPC_HEADER_RE.search(resp_headers) or
                    r.status_code in (200,) and "reflection" in path.lower()
                )

                if not is_grpc:
                    continue

                if "reflection" in path.lower():
                    found_reflection = True
                    log_fail(logger, f"gRPC reflection API exposed: {probe_url}")
                    self.results.append(self._result(
                        probe_url, "gRPC — reflection API exposed (full service enumeration)", "FAIL",
                        detail=(
                            f"gRPC Server Reflection API is enabled at {probe_url}. "
                            "The reflection API exposes all registered gRPC services and their "
                            "method signatures — equivalent to WSDL for SOAP. Attackers can "
                            "enumerate all available RPC methods and call them without needing "
                            "source code. "
                            "Fix: disable gRPC reflection in production "
                            "(reflection.Register() should only be called in dev/test); "
                            "restrict reflection to internal networks only."
                        )
                    ))
                elif "health" in path.lower():
                    found_health = True
                    log_warn(logger, f"gRPC health check endpoint exposed: {probe_url}")
                    self.results.append(self._result(
                        probe_url, "gRPC — health check endpoint accessible", "WARN",
                        detail=(
                            f"gRPC health check endpoint found at {probe_url}. "
                            "While health endpoints are intentional, ensure they don't "
                            "expose service topology or internal service names."
                        )
                    ))
                else:
                    found_grpc.append(probe_url)
                    log_warn(logger, f"gRPC endpoint found: {probe_url}")
                    self.results.append(self._result(
                        probe_url, f"gRPC — endpoint found at {path}", "WARN",
                        detail=(
                            f"gRPC endpoint accessible at {probe_url}. "
                            "Verify authentication (JWT/mTLS) is required, TLS is enforced "
                            "(gRPC should not run over plain HTTP in production), "
                            "and authorization is applied per-method."
                        )
                    ))
            except Exception:
                continue

        if not self.results:
            log_pass(logger, f"No gRPC endpoints detected on {url}")
            self.results.append(self._result(
                url, "gRPC — no gRPC endpoints detected", "PASS",
                detail="No gRPC content types, reflection API, or gRPC-specific paths found."
            ))

        return self.results
