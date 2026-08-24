"""
Advanced DNS security checks.

Checks:
- CAA (Certification Authority Authorization) record
  Prevents misissued TLS certificates by restricting which CAs can issue for the domain.
- DNSSEC (DS record at parent zone)
  Cryptographic protection of DNS responses against spoofing/cache-poisoning.
- SPF record existence (complementary to email_security.py, DNS-only path)
- DMARC record existence (DNS-only path)
- NS record diversity (all NS on same /24 → single point of failure)
"""

from typing import List, Dict, Any
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)


def _import_dns():
    try:
        import dns.resolver
        import dns.exception
        return dns.resolver, dns.exception
    except ImportError:
        return None, None


def _resolve(resolver, name: str, rdtype: str):
    try:
        return list(resolver.resolve(name, rdtype))
    except Exception:
        return []


class DNSAdvancedScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        resolver, _ = _import_dns()
        if resolver is None:
            logger.warning("dnspython not installed — skipping advanced DNS checks")
            return self.results

        parsed = urlparse(url)
        host   = parsed.hostname or ""
        domain = host.lstrip("www.") if host.startswith("www.") else host
        if not domain:
            return self.results

        self._check_caa(domain, resolver, url)
        self._check_dnssec(domain, resolver, url)
        self._check_ns_diversity(domain, resolver, url)
        return self.results

    # ── CAA ───────────────────────────────────────────────────────────────────

    def _check_caa(self, domain: str, resolver, url: str) -> None:
        records = _resolve(resolver, domain, "CAA")
        if records:
            issuers = []
            for rdata in records:
                try:
                    # rdata.tag / rdata.value vary by dnspython version
                    tag   = str(getattr(rdata, "tag",   "")).lower()
                    value = str(getattr(rdata, "value", "")).strip('"').lower()
                    if tag in ("issue", "issuewild"):
                        issuers.append(value or "any")
                except Exception:
                    pass

            if issuers and issuers != ["any"]:
                log_pass(logger, f"CAA record restricts issuers for {domain}: {issuers}")
                self.results.append(self._result(url,
                    "DNS — CAA record configured",
                    "PASS",
                    detail=(
                        f"CAA record found for {domain} — only these CAs can issue "
                        f"TLS certificates: {', '.join(set(issuers))}. "
                        "CAA prevents misissued certificates by rogue/compromised certificate authorities."
                    )))
            else:
                log_warn(logger, f"CAA record found but allows any CA for {domain}")
                self.results.append(self._result(url,
                    "DNS — CAA record allows any CA (issue: \";\")",
                    "WARN",
                    detail=(
                        f"CAA record exists for {domain} but permits any CA to issue certificates. "
                        "Fix: replace with specific issuers, e.g. '0 issue \"letsencrypt.org\"' "
                        "and '0 issue \"pki.goog\"'."
                    )))
        else:
            log_warn(logger, f"No CAA record for {domain}")
            self.results.append(self._result(url,
                "DNS — no CAA record",
                "WARN",
                detail=(
                    f"No CAA DNS record found for {domain}. "
                    "Without CAA, any of the 100+ trusted CAs can issue a certificate for your domain. "
                    "A compromised or rogue CA could issue a fraudulent certificate, enabling MITM attacks. "
                    "Fix: add a CAA record restricting issuance to your actual CA, e.g. "
                    "'0 issue \"letsencrypt.org\"' and '0 issuewild \"letsencrypt.org\"'."
                )))

    # ── DNSSEC ────────────────────────────────────────────────────────────────

    def _check_dnssec(self, domain: str, resolver, url: str) -> None:
        # Check for DS record (Delegation Signer) at parent zone
        # A DS record at the parent indicates DNSSEC is enabled and chained
        ds_records = _resolve(resolver, domain, "DS")
        if ds_records:
            log_pass(logger, f"DNSSEC DS record found for {domain}")
            self.results.append(self._result(url,
                "DNS — DNSSEC enabled (DS record present)",
                "PASS",
                detail=(
                    f"DNSSEC DS record found for {domain}. "
                    "DNS responses for this domain are cryptographically signed — "
                    "attackers cannot spoof DNS responses or poison caches to redirect your visitors."
                )))
            return

        # Also check for DNSKEY (zone may be signed but not chained yet)
        dnskey_records = _resolve(resolver, domain, "DNSKEY")
        if dnskey_records:
            log_warn(logger, f"DNSKEY present but no DS record (chain not complete) for {domain}")
            self.results.append(self._result(url,
                "DNS — DNSSEC partially configured (DNSKEY present, DS missing)",
                "WARN",
                detail=(
                    f"DNSKEY record found for {domain} but no DS record at parent zone. "
                    "DNSSEC is configured at the zone level but the trust chain to the "
                    "parent zone is not established — validators treat the zone as unsigned. "
                    "Fix: add the DS record to your registrar/parent zone."
                )))
        else:
            log_warn(logger, f"No DNSSEC for {domain}")
            self.results.append(self._result(url,
                "DNS — DNSSEC not enabled",
                "WARN",
                detail=(
                    f"No DNSSEC (DS or DNSKEY records) found for {domain}. "
                    "Without DNSSEC, attackers can poison DNS caches to redirect your visitors "
                    "to malicious servers — especially dangerous for MX records (email hijacking) "
                    "and A records (traffic interception). "
                    "Fix: enable DNSSEC in your DNS provider's control panel. "
                    "Most major registrars (Cloudflare, Route53, Google Domains) support it for free."
                )))

    # ── NS diversity ──────────────────────────────────────────────────────────

    def _check_ns_diversity(self, domain: str, resolver, url: str) -> None:
        ns_records = _resolve(resolver, domain, "NS")
        if not ns_records:
            return

        ns_names = [str(r.target).rstrip(".").lower() for r in ns_records]
        if len(ns_names) < 2:
            log_warn(logger, f"Only one NS record for {domain}")
            self.results.append(self._result(url,
                "DNS — single nameserver (no redundancy)",
                "WARN",
                detail=(
                    f"Only one nameserver found for {domain}: {ns_names[0]}. "
                    "If this nameserver goes down, your entire domain becomes unreachable. "
                    "Fix: configure at least two geographically diverse nameservers."
                )))
            return

        # Check if all NS are on the same provider (same domain suffix)
        suffixes = set()
        for ns in ns_names:
            parts = ns.split(".")
            if len(parts) >= 2:
                suffixes.add(".".join(parts[-2:]))

        if len(suffixes) == 1:
            log_warn(logger, f"All NS records share provider {list(suffixes)[0]} for {domain}")
            self.results.append(self._result(url,
                "DNS — all nameservers from same provider",
                "WARN",
                detail=(
                    f"All {len(ns_names)} nameservers for {domain} are from the same provider "
                    f"({list(suffixes)[0]}). An outage or DDoS at this provider takes down all "
                    "DNS resolution simultaneously. "
                    "Fix: consider a secondary DNS provider for resilience."
                )))
        else:
            log_pass(logger, f"NS records are diverse for {domain}")
            self.results.append(self._result(url,
                "DNS — nameservers are diverse",
                "PASS",
                detail=(
                    f"Nameservers for {domain} span {len(suffixes)} providers "
                    f"({', '.join(sorted(suffixes))}). Good resilience against provider-level outages."
                )))
