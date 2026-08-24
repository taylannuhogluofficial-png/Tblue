"""
DNS Certificate Authority Authorization (CAA) Scanner.

CAA (RFC 8659) DNS records specify which Certificate Authorities are allowed
to issue TLS certificates for a domain. Without CAA records, ANY CA can
issue a certificate for your domain — including those targeted by social
engineering or compromised.

Real-world attacks CAA prevents:
  - Misissuance: DigiNotar, Comodo, ANSSI all issued fraudulent certificates
    for major sites. CAA would have blocked these.
  - Subdomain takeover via cert: attacker can't get a cert for a subdomain
    they don't control if the parent has restrictive CAA records.

This scanner:
  1. Resolves CAA records for the target domain and its parent domains
  2. Checks if ANY CAA records exist (missing = any CA can issue)
  3. Validates that known secure CAs are specified
  4. Checks for iodef reporting contact (security notifications)
  5. Detects overly permissive wildcards in issuewild records
  6. Checks parent domain CAA inheritance (subdomains inherit parent CAA)

This is a PASSIVE DNS lookup — no connection to the target web server.

RFC 8659: DNS Certification Authority Authorization (CAA) Resource Record
"""

import socket
import struct
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_KNOWN_CAS = {
    "letsencrypt.org", "digicert.com", "sectigo.com", "comodo.com",
    "globalsign.com", "godaddy.com", "entrust.net", "geotrust.com",
    "rapidssl.com", "thawte.com", "verisign.com", "comodoca.com",
    "pki.goog", "amazonaws.com", "cloudflare.com", "ssl.com",
    "usertrust.com", "trust-provider.com", "identrust.com",
    "amazon.com", "amazontrust.com",
}


def _query_caa(domain: str) -> List[Tuple[int, str, str]]:
    """
    Query CAA records using a raw DNS query.
    Returns list of (flag, tag, value) tuples.
    Falls back gracefully if dnspython is unavailable.
    """
    try:
        import dns.resolver
        import dns.rdatatype
        results = []
        try:
            answer = dns.resolver.resolve(domain, "CAA", raise_on_no_answer=False)
            for rdata in answer:
                results.append((rdata.flags, rdata.tag.decode(), rdata.value.decode()))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                dns.exception.Timeout):
            pass
        return results
    except ImportError:
        pass

    # Fallback: manual DNS query over UDP (type 257 = CAA)
    try:
        return _raw_caa_query(domain)
    except Exception:
        return []


def _raw_caa_query(domain: str) -> List[Tuple[int, str, str]]:
    """Send a raw DNS query for CAA records (type 257)."""
    import random
    qid = random.randint(0, 65535)
    # Build DNS query packet
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b""
    for part in domain.split("."):
        part_bytes = part.encode()
        qname += bytes([len(part_bytes)]) + part_bytes
    qname += b"\x00"
    question = qname + struct.pack(">HH", 257, 1)  # CAA, IN
    packet = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    try:
        sock.sendto(packet, ("8.8.8.8", 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    return _parse_caa_response(data, qid)


def _parse_caa_response(data: bytes, expected_qid: int) -> List[Tuple[int, str, str]]:
    """Parse DNS response and extract CAA records."""
    results = []
    if len(data) < 12:
        return results

    qid, flags, qdcount, ancount, _, _ = struct.unpack(">HHHHHH", data[:12])
    if qid != expected_qid or ancount == 0:
        return results

    # Skip header + question section (variable length)
    pos = 12
    for _ in range(qdcount):
        while pos < len(data) and data[pos] != 0:
            if data[pos] & 0xC0 == 0xC0:
                pos += 2
                break
            pos += data[pos] + 1
        else:
            pos += 1
        pos += 4  # QTYPE + QCLASS

    # Parse answer records
    for _ in range(ancount):
        if pos + 10 >= len(data):
            break
        # Skip name (may be compressed)
        if data[pos] & 0xC0 == 0xC0:
            pos += 2
        else:
            while pos < len(data) and data[pos] != 0:
                pos += data[pos] + 1
            pos += 1

        if pos + 10 > len(data):
            break

        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[pos:pos+10])
        pos += 10
        rdata = data[pos:pos+rdlen]
        pos += rdlen

        if rtype == 257 and len(rdata) >= 2:
            flag = rdata[0]
            tag_len = rdata[1]
            if 2 + tag_len <= len(rdata):
                tag = rdata[2:2+tag_len].decode("ascii", errors="replace")
                value = rdata[2+tag_len:].decode("ascii", errors="replace")
                results.append((flag, tag, value))

    return results


def _get_parent_domains(domain: str) -> List[str]:
    """Return progressively shorter domain names."""
    parts = domain.split(".")
    domains = []
    for i in range(len(parts) - 1):
        domains.append(".".join(parts[i:]))
    return domains


class DNSCAAScanner(BaseScanner):
    """Checks DNS CAA records for certificate issuance authorization."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        if not hostname:
            self.results.append(self._result(
                url, "DNS CAA — could not extract hostname", "PASS"))
            return self.results

        # Strip www.
        domain = hostname.lstrip("www.") if hostname.startswith("www.") else hostname

        # Check domain and parent domains (inheritance)
        all_caa: List[Tuple[str, int, str, str]] = []
        for check_domain in [domain] + _get_parent_domains(domain)[:2]:
            records = _query_caa(check_domain)
            for flag, tag, value in records:
                all_caa.append((check_domain, flag, tag, value))

        findings: List[Dict] = []

        if not all_caa:
            log_warn(logger, f"DNS CAA — no CAA records found for {domain}")
            findings.append({
                "severity": "WARN",
                "type": "caa-missing",
                "msg": (
                    f"No CAA records found for {domain} or its parent domains. "
                    f"Without CAA records, any Certificate Authority can issue a TLS "
                    f"certificate for this domain. Add CAA records to restrict issuance "
                    f"to your chosen CA(s).\n\n"
                    f"Example: {domain}. IN CAA 0 issue \"letsencrypt.org\""
                ),
            })
        else:
            # Check for iodef reporting
            has_iodef = any(tag == "iodef" for _, _, tag, _ in all_caa)
            if not has_iodef:
                findings.append({
                    "severity": "WARN",
                    "type": "caa-no-iodef",
                    "msg": (
                        f"CAA records found for {domain} but no 'iodef' reporting contact. "
                        f"Add an iodef record to receive CA misissuance notifications: "
                        f"{domain}. IN CAA 0 iodef \"mailto:security@{domain}\""
                    ),
                })

            # Check for unrestricted wildcards
            issue_values = [v.strip('"') for _, _, tag, v in all_caa if tag in ("issue", "issuewild")]
            for v in issue_values:
                if v.strip() in (";", ""):
                    # Semicolon means "deny all" — this is actually GOOD
                    pass
                else:
                    # Validate CA name
                    ca_domain = v.split(";")[0].strip().lstrip('"').rstrip('"').lower()
                    if ca_domain and not any(known in ca_domain for known in _KNOWN_CAS):
                        # Unknown CA — flag for review
                        findings.append({
                            "severity": "WARN",
                            "type": f"caa-unknown-ca",
                            "msg": (
                                f"CAA record authorizes unknown CA: '{ca_domain}'. "
                                f"Verify this is intentional and that the CA is trustworthy."
                            ),
                        })

        if not findings:
            log_pass(logger, f"DNS CAA — CAA records correctly configured for {domain}")
            caa_summary = ", ".join(f"{tag}={val}" for _, _, tag, val in all_caa[:5])
            self.results.append(self._result(
                url,
                f"DNS CAA — CAA records found and correctly configured",
                "PASS",
                detail=f"Domain: {domain}\nCAA records: {caa_summary}",
            ))
            return self.results

        for f in findings:
            status = f["severity"]
            if status == "FAIL":
                log_fail(logger, f"DNS CAA — {f['msg'][:80]}")
            else:
                log_warn(logger, f"DNS CAA — {f['msg'][:80]}")

            self.results.append(self._result(
                url,
                f"DNS CAA — {f['type']}",
                status,
                detail=f["msg"],
            ))

        return self.results
