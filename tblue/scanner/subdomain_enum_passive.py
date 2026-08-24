"""
Passive Subdomain Enumeration Scanner.

Discovers subdomains by querying public passive-DNS and CT log sources:

1. crt.sh — Certificate Transparency log search (no API key required)
2. HackerTarget passive DNS API (no key required, rate-limited)
3. Detects wildcard certificate coverage (*.example.com)
4. Flags high-value subdomains: dev, staging, api, admin, vpn, mail, jenkins, gitlab, jira

All lookups are passive — no DNS brute force, no active probing of found subdomains.
"""

import re
import json
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_CRTSH_URL       = "https://crt.sh/?q={domain}&output=json"
_HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"

_HIGH_VALUE_PATTERNS = re.compile(
    r'^(?:dev|staging|stage|uat|qa|test|demo|beta|internal|api|admin|vpn|'
    r'jenkins|gitlab|jira|confluence|bitbucket|sonar|nexus|harbor|'
    r'mail|smtp|ftp|sftp|ssh|rdp|bastion|jump|mgmt|monitor|grafana|'
    r'kibana|elastic|splunk|consul|vault|k8s|kube|rancher|portainer)\.',
    re.I,
)

_WILDCARD_RE = re.compile(r'^\*\.')


class SubdomainEnumPassiveScanner(BaseScanner):
    """Discover subdomains passively via CT logs and passive DNS APIs."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed  = urlparse(url)
        domain  = parsed.hostname or ""
        if not domain:
            return self.results

        # Strip www prefix to get root domain for enumeration
        root = re.sub(r'^www\.', '', domain)

        subdomains: Set[str] = set()
        wildcards:  Set[str] = set()

        self._query_crtsh(url, root, subdomains, wildcards)
        self._query_hackertarget(url, root, subdomains)

        self._report_findings(url, domain, root, subdomains, wildcards)

        if not self.results:
            log_pass(logger, f"Passive subdomain enumeration found nothing notable for {root}")
            self.results.append(self._result(
                url, "Subdomain enum — no sensitive subdomains found passively", "PASS",
                detail=(
                    f"Passive CT log and DNS enumeration found no high-value subdomains "
                    f"for {root}."
                )
            ))

        return self.results

    def _query_crtsh(self, url: str, domain: str, subs: Set[str], wildcards: Set[str]) -> None:
        try:
            resp = self.http.get(_CRTSH_URL.format(domain=domain))
            if resp is None or resp.status_code != 200:
                return
            entries = json.loads(resp.text)
            for entry in entries:
                name = entry.get("name_value", "")
                for name_part in name.split("\n"):
                    name_part = name_part.strip().lower()
                    if not name_part:
                        continue
                    if _WILDCARD_RE.match(name_part):
                        wildcards.add(name_part)
                    elif name_part.endswith(f".{domain}") or name_part == domain:
                        subs.add(name_part)
        except Exception:
            pass

    def _query_hackertarget(self, url: str, domain: str, subs: Set[str]) -> None:
        try:
            resp = self.http.get(_HACKERTARGET_URL.format(domain=domain))
            if resp is None or resp.status_code != 200:
                return
            if "error" in resp.text.lower() and "API count" in resp.text:
                return
            for line in resp.text.splitlines():
                if "," in line:
                    subdomain = line.split(",")[0].strip().lower()
                    if subdomain.endswith(f".{domain}"):
                        subs.add(subdomain)
        except Exception:
            pass

    def _report_findings(
        self,
        url: str,
        domain: str,
        root: str,
        subs: Set[str],
        wildcards: Set[str],
    ) -> None:
        if wildcards:
            wc_list = ", ".join(sorted(wildcards)[:10])
            log_warn(logger, f"Wildcard TLS certificate found: {wc_list}")
            self.results.append(self._result(
                url, "Subdomain enum — wildcard certificate in CT logs", "WARN",
                detail=(
                    f"Wildcard TLS certificate(s) found in Certificate Transparency logs for {root}: "
                    f"{wc_list}. "
                    "Wildcard certificates mask which specific subdomains exist, complicating "
                    "revocation and monitoring. Any compromised private key covers all subdomains."
                )
            ))

        high_value = [s for s in subs if _HIGH_VALUE_PATTERNS.match(s)]
        if high_value:
            hv_sorted = sorted(high_value)[:20]
            log_warn(logger, f"High-value subdomains discovered: {', '.join(hv_sorted[:5])}...")
            self.results.append(self._result(
                url, f"Subdomain enum — {len(high_value)} high-value subdomain(s) discovered", "WARN",
                detail=(
                    f"Passive enumeration found {len(high_value)} high-value subdomain(s) for {root} "
                    f"in public CT logs or passive DNS: {', '.join(hv_sorted)}. "
                    "These likely expose development environments, admin panels, CI/CD systems, "
                    "or internal tools. Verify each is properly access-controlled and not publicly "
                    "accessible without authentication."
                )
            ))

        total = len(subs)
        if total > 5:
            log_warn(logger, f"{total} total subdomains found passively for {root}")
            self.results.append(self._result(
                url, f"Subdomain enum — {total} subdomains in CT/passive DNS", "WARN",
                detail=(
                    f"Certificate Transparency logs and passive DNS reveal {total} subdomains "
                    f"for {root}. A large subdomain footprint increases attack surface. "
                    "Review each subdomain for stale/decommissioned services, missing security "
                    "headers, and subdomain takeover risk."
                )
            ))
