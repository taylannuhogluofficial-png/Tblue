"""
DNS security scanner.

Two checks in one module:

1. DNSSEC — verifies the domain has DNSSEC signing configured.
   Queries DNSKEY records at the zone apex. Missing DNSKEY = WARN
   (domain is vulnerable to cache-poisoning / Kaminsky-style attacks).

2. Subdomain surface scan — resolves ~25 common subdomain names via DNS.
   Results are INFO (not failures) — the value is showing site owners
   their full attack surface so they can audit unexpected exposure.
   Purely defensive: no HTTP probing, just DNS A/AAAA lookups.
"""

from typing import List, Dict, Any
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_COMMON_SUBDOMAINS = [
    "api", "admin", "staging", "dev", "test", "beta",
    "mail", "webmail", "smtp", "vpn", "ssh", "ftp",
    "dashboard", "portal", "app", "cdn", "static",
    "assets", "media", "docs", "developer", "internal",
    "auth", "login", "sso", "legacy",
]


def _import_dns():
    try:
        import dns.resolver
        import dns.exception
        # NXDOMAIN lives in dns.resolver, not dns.exception
        return dns.resolver, dns.exception
    except ImportError:
        return None, None


def _nxdomain_exc():
    try:
        import dns.resolver
        return dns.resolver.NXDOMAIN
    except Exception:
        return Exception


class DNSSecurityScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        dns_resolver, dns_exception = _import_dns()

        domain = _extract_domain(url)
        if not domain:
            return self.results

        if dns_resolver is None:
            logger.warning("dnspython not installed — skipping DNS security checks")
            return self.results

        self._check_dnssec(domain, dns_resolver, dns_exception)
        self._scan_subdomains(domain, dns_resolver, dns_exception)
        return self.results

    def _check_dnssec(self, domain: str, resolver, exc_module) -> None:
        try:
            answers = resolver.resolve(domain, "DNSKEY")
            if answers:
                log_pass(logger, f"DNSSEC configured — {domain}")
                self.results.append(self._result(
                    domain, "DNSSEC — configured", "PASS",
                    detail=(
                        f"DNSKEY records found for {domain}. "
                        "DNSSEC is configured, protecting against DNS cache poisoning "
                        "and man-in-the-middle DNS attacks."
                    )
                ))
        except Exception as e:
            # NXDOMAIN is in dns.resolver; NoAnswer/NoNameservers in dns.exception
            # Catch all DNS errors and treat as "not configured"
            reason = "no DNSKEY records" if "NoAnswer" in type(e).__name__ else str(type(e).__name__)
            logger.debug(f"DNSSEC check error for {domain}: {e}")
            self._dnssec_warn(domain, reason)

    def _dnssec_warn(self, domain: str, reason: str) -> None:
        log_warn(logger, f"DNSSEC not detected ({reason}) — {domain}")
        self.results.append(self._result(
            domain, "DNSSEC — not configured", "WARN",
            detail=(
                f"No DNSKEY records found for {domain} ({reason}). "
                "Without DNSSEC, DNS responses for your domain can be forged by "
                "cache-poisoning attacks, redirecting your users to attacker-controlled servers. "
                "Fix: enable DNSSEC at your DNS registrar or nameserver. "
                "Most major registrars (Cloudflare, Route53, Google Domains) support DNSSEC "
                "with one-click enablement."
            )
        ))

    def _scan_subdomains(self, domain: str, resolver, exc_module) -> None:
        found: List[Dict[str, str]] = []

        for sub in _COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{domain}"
            try:
                answers = resolver.resolve(fqdn, "A")
                ips = [r.address for r in answers]
                found.append({"subdomain": fqdn, "ips": ", ".join(ips)})
            except Exception:
                pass

        if found:
            subdomain_list = ", ".join(f["subdomain"] for f in found[:10])
            more = f" (+ {len(found) - 10} more)" if len(found) > 10 else ""
            logger.info(f"Subdomains found for {domain}: {subdomain_list}{more}")
            self.results.append(self._result(
                domain, "Subdomain surface — active subdomains found", "PASS",
                detail=(
                    f"Found {len(found)} active subdomain(s) for {domain}: "
                    f"{subdomain_list}{more}. "
                    "Review this list — each active subdomain is part of your attack surface. "
                    "Ensure staging/dev/test subdomains are not publicly accessible, "
                    "have the same security controls as production, "
                    "and do not host sensitive data."
                ),
                extra={"subdomains": found}
            ))
        else:
            log_pass(logger, f"No common subdomains found for {domain}")
            self.results.append(self._result(
                domain, "Subdomain surface — no common subdomains exposed", "PASS",
                detail=(
                    f"None of the {len(_COMMON_SUBDOMAINS)} common subdomain names "
                    f"resolve for {domain}."
                )
            ))

    def _result(self, url, result_type, status, detail="", extra=None):
        r = super()._result(url, result_type, status, detail=detail)
        if extra:
            r.update(extra)
        return r


def _extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url if "://" in url else "https://" + url)
        host   = parsed.hostname or ""
        return host.lstrip("www.") if host.startswith("www.") else host
    except Exception:
        return ""
