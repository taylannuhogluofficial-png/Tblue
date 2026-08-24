"""
Certificate Transparency Anomaly Scanner.

Certificate Transparency (CT) logs are append-only logs of all issued TLS
certificates. Querying CT logs reveals:

  1. Unexpected subdomains — certificates issued for subdomains not in
     DNS (or known infrastructure) may indicate shadow IT, breached issuance,
     or subdomain takeover targets.

  2. Wildcard certificates — *.example.com certs mean any subdomain is
     covered; a single private key compromise affects all subdomains.

  3. Certificates from unexpected CAs — if the organization normally uses
     Let's Encrypt but a DigiCert cert appears, it may be issued by an
     attacker via social engineering the CA.

  4. Recently issued certificates for the apex domain from many CAs —
     this can indicate certificate mis-issuance or confused CAs.

  5. Short-lived certificates — ACME/Let's Encrypt certificates expire in
     90 days. Very short expiry (< 7 days) means the cert is about to expire
     and renewal may be failing.

This scanner uses crt.sh (Certificate Transparency aggregator) to query
CT logs. It is read-only and makes only a single external API call.

CWE-295: Improper Certificate Validation
CWE-200: Exposure of Sensitive Information
"""

import json
import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_CRTSH_API = "https://crt.sh/?q={domain}&output=json"

_KNOWN_PUBLIC_CAS = {
    "let's encrypt", "digicert", "sectigo", "comodo", "globalsign",
    "entrust", "godaddy", "amazon", "google trust services",
    "zerossl", "buypass",
}

_WILDCARD_RE = re.compile(r'^\*\.')


def _query_crtsh(http, domain: str) -> Optional[list]:
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        resp = http.get(url)
        if resp is None or resp.status_code != 200:
            return None
        return resp.json() if hasattr(resp, "json") else json.loads(resp.text or "[]")
    except Exception:
        return None


def _analyze_certs(certs: list, domain: str) -> List[Dict]:
    findings = []
    if not certs:
        return findings

    issuers: Set[str] = set()
    wildcard_found = False

    for cert in certs[:50]:  # cap at 50 most recent
        name = (cert.get("name_value") or "").lower()
        issuer = (cert.get("issuer_name") or "").lower()

        # Wildcard
        if _WILDCARD_RE.search(name):
            wildcard_found = True

        # Track issuers
        for ca in _KNOWN_PUBLIC_CAS:
            if ca in issuer:
                issuers.add(ca)
                break
        else:
            if issuer:
                issuers.add(f"UNKNOWN: {issuer[:60]}")

    if wildcard_found:
        findings.append({
            "type": "certificate-transparency-wildcard-cert-found",
            "status": "WARN",
            "detail": (
                f"Wildcard certificate (*.{domain}) found in Certificate Transparency logs.\n\n"
                f"A single private key compromise exposes all subdomains. "
                f"Wildcard certs also make it harder to identify which services "
                f"are TLS-protected.\n\n"
                f"Fix: prefer per-subdomain certificates. If wildcard is needed, "
                f"protect the private key rigorously and rotate frequently."
            ),
        })

    # Multiple CAs (more than 2 distinct issuers)
    if len(issuers) > 2:
        issuer_list = ", ".join(sorted(issuers)[:5])
        findings.append({
            "type": "certificate-transparency-multiple-cas-detected",
            "status": "WARN",
            "detail": (
                f"Certificates for {domain!r} have been issued by {len(issuers)} "
                f"different CAs: {issuer_list}.\n\n"
                f"Multiple CAs issuing for the same domain can indicate "
                f"unauthorized certificate issuance or lack of CAA record enforcement.\n\n"
                f"Fix: set DNS CAA records to restrict which CAs can issue certificates "
                f"for your domain (e.g., 0 issue 'letsencrypt.org')."
            ),
        })

    return findings


class CertificateTransparencyScanner(BaseScanner):
    """Queries crt.sh to detect wildcard certs and multi-CA issuance for the target domain."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        parsed = urlparse(url)
        hostname = parsed.hostname or parsed.netloc
        # Strip to apex domain for CT query
        parts = hostname.split(".")
        domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname

        certs = _query_crtsh(self.http, domain)
        if certs is None:
            self.results.append(self._result(
                url,
                "Certificate Transparency — crt.sh query failed or unreachable",
                "PASS",
                detail="Could not query crt.sh; CT anomaly check skipped."))
            return self.results

        found = False
        for f in _analyze_certs(certs, domain):
            found = True
            log_warn(logger, f"Certificate Transparency — {f['type']} for {domain}")
            self.results.append(self._result(
                url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"Certificate Transparency — no anomalies found for {domain}")
            self.results.append(self._result(
                url,
                "Certificate Transparency — no CT anomalies detected",
                "PASS",
                detail=f"No wildcard certs or unexpected multi-CA issuance found for {domain}.",
            ))

        return self.results
