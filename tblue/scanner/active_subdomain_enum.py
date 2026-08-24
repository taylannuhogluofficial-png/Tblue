"""Active Subdomain Enumeration — DNS-resolve common subdomains to discover exposed attack surface."""
import re
import socket
from urllib.parse import urlparse
from .base import BaseScanner

active = True

_ASE_ANY_RE = re.compile(r'^https?://', re.I)

# 120 high-value subdomains: admin/internal surfaces, development, CI/CD, cloud, APIs, staging
_WORDLIST = [
    # Administrative / internal
    "admin", "administrator", "manage", "management", "panel", "control",
    "dashboard", "portal", "console", "backend", "backoffice", "cpanel",
    "phpmyadmin", "adminer", "db", "database",
    # Development / staging
    "dev", "develop", "development", "staging", "stage", "test", "testing",
    "qa", "uat", "beta", "alpha", "preview", "demo", "sandbox",
    "preprod", "pre-prod", "pre", "stg", "dev2", "test2",
    # Internal tooling
    "jenkins", "ci", "cd", "build", "deploy", "gitlab", "github",
    "bitbucket", "bamboo", "teamcity", "circleci", "travis",
    "sonar", "sonarqube", "nexus", "artifactory", "jira", "confluence",
    "wiki", "docs", "documentation", "kb", "knowledge",
    # Monitoring / observability
    "monitor", "monitoring", "grafana", "prometheus", "kibana", "elastic",
    "splunk", "datadog", "newrelic", "sentry", "logs", "logging",
    "metrics", "status", "health",
    # Cloud / infrastructure
    "vault", "consul", "nomad", "k8s", "kubernetes", "rancher",
    "portainer", "registry", "docker", "containers",
    "internal", "private", "intranet", "corp", "corporate",
    # APIs
    "api", "api2", "apiv2", "v1", "v2", "api-v1", "api-v2",
    "rest", "graphql", "grpc", "ws", "websocket",
    # Authentication
    "auth", "sso", "login", "oauth", "identity", "idp", "saml",
    "iam", "keycloak", "okta", "ldap", "ad",
    # Mail
    "mail", "email", "smtp", "imap", "webmail", "mx", "owa",
    # Storage
    "cdn", "assets", "static", "media", "upload", "uploads", "files",
    "backup", "backups", "archive", "store",
    # VPN / remote
    "vpn", "remote", "rdp", "bastion", "jump", "gateway", "proxy",
    # Support
    "support", "helpdesk", "ticket", "crm", "erp",
]

# Categories that indicate high-severity exposure
_HIGH_SEVERITY_PREFIXES = {
    "admin", "administrator", "manage", "management", "panel", "control",
    "dashboard", "portal", "console", "backend", "backoffice", "cpanel",
    "phpmyadmin", "adminer", "jenkins", "ci", "cd", "build", "deploy",
    "gitlab", "sonar", "sonarqube", "vault", "k8s", "kubernetes",
    "internal", "private", "intranet", "corp", "corporate",
    "grafana", "kibana", "prometheus", "elastic", "splunk",
    "portainer", "registry", "docker", "backup", "backups",
    "rdp", "bastion", "vpn",
}

_DEV_PREFIXES = {
    "dev", "develop", "development", "staging", "stage", "test", "testing",
    "qa", "uat", "beta", "alpha", "preview", "demo", "sandbox",
    "preprod", "pre-prod", "pre", "stg", "dev2", "test2",
}


def _resolve(hostname: str, timeout: float = 2.0) -> str | None:
    """Return IP address if hostname resolves, else None."""
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyname(hostname)
    except (socket.gaierror, socket.timeout):
        return None
    finally:
        socket.setdefaulttimeout(old)


def _extract_base_domain(host: str) -> str:
    """Extract registrable domain (example.com from sub.example.com)."""
    parts = host.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


class ActiveSubdomainEnumScanner(BaseScanner):
    def scan(self, url: str) -> list:
        if not _ASE_ANY_RE.match(url):
            return [self._result(url, "active_subdomain_enum_not_used", "PASS")]

        parsed = urlparse(url)
        host = parsed.hostname or ""
        if not host or re.match(r'^\d+\.\d+\.\d+\.\d+$', host):
            return [self._result(url, "active_subdomain_enum_ip_target", "INFO",
                                  detail="Target is an IP address — subdomain enumeration requires a domain name.")]

        base_domain = _extract_base_domain(host)
        findings = []
        found_subs = []

        for sub in _WORDLIST:
            fqdn = f"{sub}.{base_domain}"
            if fqdn == host:
                continue
            ip = _resolve(fqdn)
            if ip:
                found_subs.append((sub, fqdn, ip))

        for sub, fqdn, ip in found_subs:
            if sub in _HIGH_SEVERITY_PREFIXES:
                severity = "FAIL"
                context = "high-value administrative or infrastructure subdomain"
            elif sub in _DEV_PREFIXES:
                severity = "WARN"
                context = "development/staging environment"
            else:
                severity = "INFO"
                context = "auxiliary service subdomain"

            findings.append(self._result(
                url,
                f"active_subdomain_{sub}_found",
                severity,
                detail=f"Subdomain found: {fqdn} → {ip} ({context}) — verify this host is intentionally internet-accessible, has authentication enabled, has TLS configured, and is patched; development environments often have weaker security posture than production.",
            ))

        if not found_subs:
            return [self._result(url, "active_subdomain_enum_minimal_surface", "PASS",
                                  detail=f"Subdomain enumeration: 0 of {len(_WORDLIST)} common subdomains resolved for {base_domain} — low administrative/development surface exposure detected.")]

        summary = self._result(
            url, "active_subdomain_enum_summary", "INFO",
            detail=f"Subdomain enumeration complete: {len(found_subs)} of {len(_WORDLIST)} subdomains resolved for {base_domain} — review each finding above; prioritize admin/internal/CI surfaces for immediate access control verification.",
        )
        return findings + [summary]
