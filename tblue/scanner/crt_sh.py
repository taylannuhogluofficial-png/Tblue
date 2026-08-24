"""
Certificate Transparency subdomain discovery via crt.sh.

Queries the public crt.sh API (no key, no registration) for all TLS certificates
ever issued for the target domain. Returns every unique subdomain found in
certificate Subject Alternative Names — often far more complete than DNS
brute-force because it includes historical infrastructure, shadow IT, and
services that have been decommissioned but whose DNS still resolves.
"""

from typing import List, Dict, Any, Set
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_CRT_SH_URL  = "https://crt.sh/?q=%.{domain}&output=json"
_TIMEOUT     = 15


class CRTShScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        host   = urlparse(url).hostname or ""
        domain = host.lstrip("www.") if host.startswith("www.") else host
        if not domain:
            return self.results

        subdomains = self._query_crt_sh(domain)
        if subdomains is None:
            # Network error — skip silently
            return self.results

        # Filter to actual subdomains (not the apex domain itself)
        subs = sorted({s for s in subdomains
                       if s != domain and s.endswith("." + domain)
                       and "*" not in s})

        if subs:
            preview = ", ".join(subs[:15])
            more    = f" (+ {len(subs) - 15} more)" if len(subs) > 15 else ""
            log_warn(logger, f"crt.sh found {len(subs)} subdomains for {domain}")
            self.results.append(self._result(url,
                "Certificate Transparency — subdomains found in CT logs",
                "PASS",
                detail=(
                    f"crt.sh CT log query found {len(subs)} unique subdomain(s) ever issued "
                    f"certificates for {domain}: {preview}{more}. "
                    "These represent your historical and current attack surface. "
                    "Check each for: unexpected exposure, outdated software, missing security "
                    "headers, and services you thought were decommissioned. "
                    "CT logs are public and searchable by anyone — attackers use them for "
                    "target reconnaissance."
                ),
                extra={"ct_subdomains": subs[:50]}  # cap at 50 to keep response size bounded
            ))
        else:
            log_pass(logger, f"No additional subdomains in CT logs for {domain}")
            self.results.append(self._result(url,
                "Certificate Transparency — no additional subdomains in CT logs",
                "PASS",
                detail=f"crt.sh found no additional subdomains for {domain} beyond the apex domain."))

        return self.results

    def _query_crt_sh(self, domain: str):
        query_url = _CRT_SH_URL.format(domain=domain)
        try:
            resp = self.http.get(query_url)
            if not resp or resp.status_code != 200:
                logger.debug(f"crt.sh returned {resp.status_code if resp else 'no response'}")
                return None
            data: List[dict] = resp.json()
        except Exception as e:
            logger.debug(f"crt.sh query failed: {e}")
            return None

        found: Set[str] = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name:
                    found.add(name)
        return found

    def _result(self, url, result_type, status, detail="", extra=None):
        r = super()._result(url, result_type, status, detail=detail)
        if extra:
            r.update(extra)
        return r
