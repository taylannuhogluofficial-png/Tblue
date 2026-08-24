"""
Open port scanner for Tblue.

Checks if dangerous or unexpected ports are publicly reachable on the target host.
Uses concurrent TCP connect probes with short timeouts — no service fingerprinting.
This is a defensive (blue team) check: "can the internet reach your database?"
"""

import socket
import concurrent.futures
from typing import List, Dict, Any, Tuple
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_CONNECT_TIMEOUT = 1.5   # seconds per port — keep low for UX
_MAX_WORKERS     = 20    # concurrent probes

# (port, service_name, severity, description, fix)
_PORTS: List[Tuple[int, str, str, str, str]] = [
    (21,    "FTP",           "WARN",
     "Unencrypted file transfer protocol is accessible.",
     "Disable FTP. Use SFTP (port 22) or FTPS instead."),
    (22,    "SSH",           "WARN",
     "SSH port is accessible from the internet.",
     "Restrict SSH access to known IPs via firewall rules. Enable key-based auth and disable root login."),
    (23,    "Telnet",        "FAIL",
     "Telnet is unencrypted — all traffic including credentials is sent in plaintext.",
     "Disable Telnet immediately. Use SSH instead."),
    (25,    "SMTP",          "WARN",
     "SMTP port is accessible. May enable open relay if misconfigured.",
     "Restrict port 25 to known mail server IPs. Ensure relay restrictions are enforced."),
    (3306,  "MySQL",         "FAIL",
     "MySQL database port is exposed to the internet. Default MySQL has no TLS.",
     "Bind MySQL to 127.0.0.1 in my.cnf: bind-address=127.0.0.1. Use a tunnel or VPN for remote access."),
    (5432,  "PostgreSQL",    "FAIL",
     "PostgreSQL database port is exposed to the internet.",
     "Restrict PostgreSQL to localhost in postgresql.conf: listen_addresses = 'localhost'."),
    (6379,  "Redis",         "FAIL",
     "Redis port is exposed. Redis has no authentication by default and no TLS.",
     "Bind Redis to localhost (bind 127.0.0.1 in redis.conf). Add requirepass for auth. Never expose to internet."),
    (27017, "MongoDB",       "FAIL",
     "MongoDB port is exposed. Default MongoDB config has no authentication.",
     "Enable MongoDB auth (security.authorization: enabled) and bind to localhost."),
    (9200,  "Elasticsearch", "FAIL",
     "Elasticsearch REST API is exposed. Default config has no authentication.",
     "Enable Elasticsearch security (xpack.security.enabled: true) and restrict to localhost or VPN."),
    (5601,  "Kibana",        "WARN",
     "Kibana dashboard is publicly accessible.",
     "Place Kibana behind an authenticated reverse proxy. Restrict to internal network."),
    (5984,  "CouchDB",       "FAIL",
     "CouchDB admin interface is exposed to the internet.",
     "Bind CouchDB to localhost and enable authentication in couch.ini."),
    (11211, "Memcached",     "FAIL",
     "Memcached has no authentication and is used in DDoS amplification attacks.",
     "Bind Memcached to 127.0.0.1: memcached -l 127.0.0.1. Never expose to internet."),
    (3389,  "RDP",           "FAIL",
     "Remote Desktop Protocol is exposed. Primary target for ransomware operators.",
     "Move RDP behind a VPN. Restrict to known IPs. Enable NLA. Disable if not needed."),
    (2375,  "Docker API",    "FAIL",
     "Docker daemon API is exposed without TLS — full root-level server compromise is trivial.",
     "Never expose Docker socket to internet. Use Docker TLS (port 2376) or restrict via unix socket."),
    (2376,  "Docker TLS",    "WARN",
     "Docker daemon API with TLS is exposed. Verify client certificate requirements.",
     "Restrict Docker TLS access to known IP ranges. Rotate certificates regularly."),
    (10250, "Kubelet",       "FAIL",
     "Kubernetes Kubelet API is exposed — container escape to host is possible.",
     "Restrict Kubelet access to the control plane network only via network policies and firewall rules."),
    (8080,  "HTTP alt",      "WARN",
     "Alternative HTTP port is accessible. Often used for admin panels or debug servers.",
     "Verify what is running on port 8080. Move admin interfaces behind auth and VPN."),
    (8443,  "HTTPS alt",     "WARN",
     "Alternative HTTPS port is accessible.",
     "Verify what is running on port 8443. Ensure it requires authentication."),
    (9090,  "Prometheus",    "WARN",
     "Prometheus metrics endpoint is publicly accessible. Exposes infrastructure details.",
     "Restrict Prometheus to internal network. Add HTTP basic auth or use a reverse proxy with auth."),
    (9000,  "PHP-FPM / misc","WARN",
     "Port 9000 is accessible. PHP-FPM on this port should never be internet-facing.",
     "Bind PHP-FPM to a unix socket instead of TCP port, or restrict to localhost only."),
    (4848,  "GlassFish admin","FAIL",
     "GlassFish administration console is publicly accessible.",
     "Restrict the GlassFish admin console to localhost or a management VPN."),
    (7001,  "WebLogic",      "FAIL",
     "WebLogic admin server port is exposed. Historically high-value exploit target.",
     "Restrict WebLogic admin port to internal management network only."),
    (8161,  "ActiveMQ admin","FAIL",
     "ActiveMQ admin console is publicly accessible.",
     "Restrict ActiveMQ admin access to localhost or internal network."),
    (4369,  "Erlang/RabbitMQ","FAIL",
     "Erlang Port Mapper (epmd) is accessible. Used to discover RabbitMQ/Erlang cluster nodes.",
     "Block port 4369 at firewall level. Never expose Erlang cluster communication to internet."),
    (15672, "RabbitMQ mgmt", "WARN",
     "RabbitMQ management console is publicly accessible.",
     "Place RabbitMQ management UI behind a reverse proxy with authentication."),
]

_PORT_MAP = {p: (name, sev, desc, fix) for p, name, sev, desc, fix in _PORTS}


def _tcp_open(host: str, port: int) -> bool:
    """Return True if a TCP connection to host:port succeeds within timeout."""
    try:
        with socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT):
            return True
    except OSError:
        return False


class PortScanner(BaseScanner):
    """
    Checks whether dangerous ports are reachable on the target host from the internet.

    Uses concurrent TCP connect probes. No service fingerprinting or banner grabbing.
    This is a purely defensive check — it's the equivalent of asking
    'can any random person on the internet reach your database?'
    """

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        host = _extract_host(url)
        if not host:
            return self.results

        open_ports:   List[Tuple[int, str, str, str, str]] = []
        closed_ports: List[int] = []

        ports_to_scan = [p for p, *_ in _PORTS]

        with concurrent.futures.ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
            future_to_port = {executor.submit(_tcp_open, host, p): p for p in ports_to_scan}
            for future in concurrent.futures.as_completed(future_to_port):
                port  = future_to_port[future]
                is_open = future.result()
                if is_open:
                    name, sev, desc, fix = _PORT_MAP[port]
                    open_ports.append((port, name, sev, desc, fix))
                else:
                    closed_ports.append(port)

        # Report open ports (sorted by port number)
        open_ports.sort(key=lambda x: x[0])
        for port, name, sev, desc, fix in open_ports:
            if sev == "FAIL":
                log_fail(logger, f"Port {port}/{name} open on {host}")
            else:
                log_warn(logger, f"Port {port}/{name} open on {host}")
            self.results.append(self._result(
                url, f"Open ports — {port}/{name}", sev,
                detail=f"{desc} Fix: {fix}"
            ))

        if not open_ports:
            log_pass(logger, f"No dangerous ports open on {host}")
            self.results.append(self._result(
                url, "Open ports — no dangerous ports exposed", "PASS",
                detail=(
                    f"None of the {len(ports_to_scan)} checked ports are publicly reachable on {host}. "
                    "Database and admin ports are properly firewalled."
                )
            ))

        return self.results


def _extract_host(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname or ""
