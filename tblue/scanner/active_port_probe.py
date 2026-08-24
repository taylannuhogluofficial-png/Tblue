"""Active Port Probe — TCP connect scan of dangerous ports on the target host."""
import re
import socket
from urllib.parse import urlparse
from .base import BaseScanner

active = True

_APP_ANY_RE = re.compile(r'^https?://', re.I)

# (port, service_name, severity, reason)
_DANGEROUS_PORTS = [
    (21,    "FTP",                  "FAIL", "FTP transmits credentials in plaintext; directory traversal and anonymous login risks; replace with SFTP or FTPS."),
    (22,    "SSH",                  "WARN", "SSH port exposed to internet — ensure key-only auth, no root login, and fail2ban or IP allowlist in place; brute-force target."),
    (23,    "Telnet",               "FAIL", "Telnet transmits all data including credentials in plaintext; no encryption; replace immediately with SSH."),
    (25,    "SMTP",                 "WARN", "SMTP exposed — potential open relay; ensure authentication required and relay restrictions configured."),
    (110,   "POP3",                 "WARN", "POP3 port exposed — use POP3S (port 995) with TLS; plaintext credential transmission over port 110."),
    (143,   "IMAP",                 "WARN", "IMAP port exposed — use IMAPS (port 993) with TLS; plaintext credential transmission over port 143."),
    (445,   "SMB/NetBIOS",          "FAIL", "SMB port exposed to internet — EternalBlue/WannaCry attack surface; block port 445 at firewall immediately; never expose SMB to internet."),
    (1433,  "MSSQL",                "FAIL", "Microsoft SQL Server exposed to internet — database port should never be internet-accessible; restrict to private network or VPN only."),
    (1521,  "Oracle DB",            "FAIL", "Oracle Database port exposed to internet — database port should never be internet-accessible; restrict to private network or VPN only."),
    (2375,  "Docker API (plaintext)","FAIL", "Docker daemon API exposed without TLS — unauthenticated HTTP access allows container management, host filesystem access, privilege escalation to root; block immediately."),
    (2376,  "Docker API (TLS)",     "WARN", "Docker daemon API exposed with TLS — verify client certificate authentication is enforced; container escape to host filesystem possible if misconfigured."),
    (3000,  "Dev server",           "WARN", "Development server port exposed — Node.js/React/Vite dev server often lacks authentication; source maps, hot-reload endpoints, and debug info exposed."),
    (3306,  "MySQL/MariaDB",        "FAIL", "MySQL database port exposed to internet — database ports must be restricted to private network; direct internet exposure enables brute-force, credential stuffing, and raw SQL access."),
    (3389,  "RDP",                  "FAIL", "RDP (Remote Desktop) exposed to internet — high-value brute-force target; BlueKeep (CVE-2019-0708) and DejaBlue exploits; restrict to VPN + NLA required."),
    (4848,  "GlassFish Admin",      "FAIL", "GlassFish application server admin console exposed — web-based admin interface with known auth bypasses; restrict to localhost only."),
    (5000,  "Dev/Flask/API",        "WARN", "Development API server port exposed — Flask debug mode, unauthenticated API, or misconfigured microservice; verify authentication and disable debug mode."),
    (5432,  "PostgreSQL",           "FAIL", "PostgreSQL database port exposed to internet — database ports must be restricted to private network; pg_hba.conf should restrict connections to localhost/VPN."),
    (5672,  "RabbitMQ AMQP",        "WARN", "RabbitMQ message broker exposed — default credentials (guest/guest) on many installations; restrict to private network."),
    (5900,  "VNC",                  "FAIL", "VNC (Virtual Network Computing) exposed to internet — GUI desktop access; many implementations have weak/no authentication; tunnel through SSH instead."),
    (5984,  "CouchDB",              "FAIL", "CouchDB HTTP API exposed — Futon/Fauxton admin interface; default no-auth configuration (admin party) on older versions; database dump via HTTP GET."),
    (6379,  "Redis",                "FAIL", "Redis exposed to internet — no authentication by default on many installations; full database read/write, config rewrite for persistence, and slave-of attack for RCE; bind to 127.0.0.1 only."),
    (7001,  "WebLogic",             "FAIL", "Oracle WebLogic admin port exposed — multiple critical RCE CVEs (CVE-2020-14882, CVE-2019-2725); restrict admin console to localhost only."),
    (8080,  "HTTP Alt",             "INFO", "Alternative HTTP port exposed — often an admin panel, Jenkins, Tomcat manager, or development server; verify authentication requirements."),
    (8161,  "ActiveMQ Admin",       "FAIL", "Apache ActiveMQ web admin console exposed — default credentials (admin/admin); known RCE via deserialization (CVE-2023-46604); restrict to localhost."),
    (8443,  "HTTPS Alt",            "INFO", "Alternative HTTPS port exposed — often admin panel or secondary web service; verify TLS configuration and access controls."),
    (8888,  "Jupyter Notebook",     "FAIL", "Jupyter Notebook port exposed — provides Python REPL with filesystem access; unauthenticated by default in older versions; arbitrary code execution on the server."),
    (9000,  "SonarQube/PHP-FPM",    "WARN", "Port 9000 exposed — SonarQube admin interface or PHP-FPM socket; verify authentication; PHP-FPM exposure enables remote code execution via crafted requests."),
    (9090,  "WildFly/Prometheus",   "WARN", "Port 9090 exposed — WildFly management console or Prometheus metrics endpoint; admin console has code execution; metrics endpoint leaks service internals."),
    (9200,  "Elasticsearch HTTP",   "FAIL", "Elasticsearch HTTP API exposed to internet — no authentication in older versions; full index read/write; data exfiltration via simple HTTP GET; bind to private network only."),
    (9300,  "Elasticsearch TCP",    "FAIL", "Elasticsearch node transport port exposed — cluster node communication; deserialization attacks; should be accessible only within the cluster private network."),
    (15672, "RabbitMQ Management",  "WARN", "RabbitMQ management UI exposed — web-based admin; default guest/guest credentials; message queue inspection and manipulation."),
    (27017, "MongoDB",              "FAIL", "MongoDB exposed to internet — no authentication on many default installs; full database read/write via HTTP-like protocol; notorious for mass data breaches; bind to 127.0.0.1 only."),
    (50000, "Jenkins",              "FAIL", "Jenkins agent port exposed — JNLP slave connection; combined with master exposure enables full CI/CD pipeline manipulation and secret exfiltration."),
    (50070, "HDFS NameNode",        "FAIL", "Hadoop HDFS NameNode WebUI exposed — read/write access to distributed filesystem without authentication; big data cluster exposure."),
]


def _tcp_connect(host: str, port: int, timeout: float = 2.0) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        return result == 0
    except (socket.timeout, socket.gaierror, OSError):
        return False
    finally:
        sock.close()


class ActivePortProbeScanner(BaseScanner):
    def scan(self, url: str) -> list:
        if not _APP_ANY_RE.match(url):
            return [self._result(url, "active_port_probe_not_used", "PASS")]

        parsed = urlparse(url)
        host = parsed.hostname or ""
        if not host:
            return [self._result(url, "active_port_probe_not_used", "PASS")]

        findings = []

        for port, service, severity, reason in _DANGEROUS_PORTS:
            if _tcp_connect(host, port):
                findings.append(self._result(
                    url, f"active_port_{port}_{service.lower().replace('/', '_').replace(' ', '_')}_open",
                    severity,
                    detail=f"Port {port}/{service} is open and reachable from the internet on {host} — {reason}",
                ))

        return findings or [self._result(url, "active_port_probe_clean", "PASS",
                                          detail=f"No dangerous ports open on {host} — all 34 scanned ports (databases, admin consoles, dev servers, remote access) are closed or filtered.")]
