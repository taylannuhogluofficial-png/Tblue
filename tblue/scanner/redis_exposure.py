"""
Redis / Memcached / Valkey exposure scanner.

Probes for publicly accessible in-memory data stores.
Redis without authentication exposes all cached data including
session tokens, API keys, and user data.
"""

import socket
import re
from typing import List, Dict, Any
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_REDIS_PORTS     = [6379, 6380, 6381]
_MEMCACHED_PORTS = [11211]
_VALKEY_PORTS    = [6379, 6380]

_HTTP_REDIS_PATHS = [
    "/redis",
    "/redis/info",
]

_REDIS_INLINE_RE  = re.compile(r"redis_version|used_memory|role:master|role:slave", re.I)
_PHPREDIS_RE      = re.compile(r"phpredis|Redis::connect|new Redis\(\)", re.I)


def _tcp_banner(host: str, port: int, send: bytes = b"PING\r\n", timeout: float = 2.0) -> str:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(send)
            return s.recv(256).decode("utf-8", errors="replace")
    except Exception:
        return ""


class RedisExposureScanner(BaseScanner):
    """Detect publicly exposed Redis / Memcached instances."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        parsed = urlparse(url)
        host   = parsed.hostname or parsed.netloc.split(":")[0]
        found  = False

        # Redis TCP banner check
        for port in _REDIS_PORTS:
            banner = _tcp_banner(host, port, b"PING\r\n")
            if "+PONG" in banner:
                found = True
                self.results.append(self._result(
                    f"redis://{host}:{port}", "redis_unauthenticated_access", "FAIL",
                    detail=f"Redis on {host}:{port} responds to PING without authentication. "
                           "Unauthenticated Redis allows reading/writing all keys, CONFIG REWRITE "
                           "(arbitrary file write as redis user), and SLAVEOF attacks. "
                           "Enable AUTH with a strong password, bind to localhost, or restrict with firewall."
                ))
            elif "NOAUTH" in banner or "ERR" in banner:
                self.results.append(self._result(
                    f"redis://{host}:{port}", "redis_auth_enforced", "PASS",
                    detail=f"Redis on {host}:{port} requires authentication (NOAUTH/ERR response to PING)."
                ))
                found = True

            # Try INFO command to check for auth requirement
            info_banner = _tcp_banner(host, port, b"INFO server\r\n")
            if _REDIS_INLINE_RE.search(info_banner):
                found = True
                # Extract version if available
                ver_m = re.search(r"redis_version:([0-9.]+)", info_banner)
                version_note = f" (Redis {ver_m.group(1)})" if ver_m else ""
                self.results.append(self._result(
                    f"redis://{host}:{port}/info", "redis_info_exposed", "FAIL",
                    detail=f"Redis INFO command responds without auth on port {port}{version_note}. "
                           "Full server configuration, memory stats, connected clients, and replication "
                           "topology exposed. Immediate authentication enforcement required."
                ))

        # Memcached check
        for port in _MEMCACHED_PORTS:
            banner = _tcp_banner(host, port, b"stats\r\n")
            if "STAT " in banner and "version" in banner.lower():
                found = True
                self.results.append(self._result(
                    f"memcached://{host}:{port}", "memcached_unauthenticated_access", "FAIL",
                    detail=f"Memcached on {host}:{port} responds to stats command without authentication. "
                           "Memcached has no native auth — all cached data is readable/writable. "
                           "Bind to localhost or use a firewall rule to restrict access."
                ))

        # HTTP-based Redis management UI probe
        for path in _HTTP_REDIS_PATHS:
            probe_url = parsed.scheme + "://" + parsed.netloc + path
            resp = self.http.get(probe_url)
            if resp and resp.status_code == 200:
                body = resp.text or ""
                if _REDIS_INLINE_RE.search(body) or "redis" in body.lower():
                    found = True
                    self.results.append(self._result(
                        probe_url, "redis_http_ui_exposed", "WARN",
                        detail=f"Redis management interface accessible at {probe_url}. "
                               "Restrict with authentication or remove from public network."
                    ))

        if not found:
            self.results.append(self._result(
                url, "redis_not_exposed", "PASS",
                detail="No publicly accessible Redis/Memcached instance detected."
            ))

        return self.results
