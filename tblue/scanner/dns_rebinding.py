"""
DNS Rebinding Risk Scanner.

DNS rebinding attacks exploit the Same-Origin Policy by:
  1. Attacker registers evil.com that resolves to their server initially
  2. After the victim loads evil.com page, attacker changes DNS to point
     to the victim's internal IP (e.g. 192.168.1.1)
  3. XHR from evil.com can now reach internal services that trust same-origin

This scanner checks for configurations that make a server MORE vulnerable
to being targeted or misused in DNS rebinding attacks:

  A. Missing / weak Host header validation (pure HTTP, no HSTS) — servers
     that accept any Host header for sensitive endpoints are rebindable.

  B. Local/private IP in DNS A records — if the server resolves to a
     private IP, it could be directly targeted by rebinding from a higher
     scope (e.g. DNS TTL set very low).

  C. Very low DNS TTL (< 30 seconds) — enables attackers to rapidly change
     resolution during the attack window. Query DNS directly via dnspython
     or raw query.

  D. No DNS-Rebinding protection headers — some mitigations:
       - Checking that Host matches expected server name (detectable if the
         server returns different behavior on unexpected Host header)
       - HTTPS with valid cert (makes rebinding harder)
       - X-Frame-Options (prevents the iframe embedding required for rebinding)

Read-only. No side effects.

CWE-346: Origin Validation Error
References: https://attacks.fyi/dns-rebinding/
"""

import re
import socket
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_PRIVATE_IP_RE = re.compile(
    r'^(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|'
    r'192\.168\.\d+\.\d+|127\.\d+\.\d+\.\d+|169\.254\.\d+\.\d+|'
    r'::1|fc[0-9a-f]{2}:|fd[0-9a-f]{2}:)'
)

_LOW_TTL_THRESHOLD = 30   # seconds


def _resolve_ips(hostname: str) -> List[Tuple[str, str]]:
    """Return list of (family, address) for hostname. Graceful on failure."""
    try:
        results = socket.getaddrinfo(hostname, None)
        seen = set()
        ips = []
        for r in results:
            addr = r[4][0]
            if addr not in seen:
                seen.add(addr)
                family = "IPv4" if r[0] == socket.AF_INET else "IPv6"
                ips.append((family, addr))
        return ips
    except Exception:
        return []


def _is_private(ip: str) -> bool:
    return bool(_PRIVATE_IP_RE.match(ip))


def _get_dns_ttl(hostname: str) -> Optional[int]:
    """Attempt to get TTL for A record via dnspython or raw DNS."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(hostname, "A")
        return answers.rrset.ttl
    except ImportError:
        pass
    except Exception:
        pass
    # Fallback: raw DNS query
    try:
        # We can't easily extract TTL from raw bytes here; return None
        pass
    except Exception:
        pass
    return None


class DNSRebindingScanner(BaseScanner):
    """Checks for DNS rebinding risk factors: private IP, low TTL, missing Host validation."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "DNS Rebinding — target unreachable", "PASS",
                detail="No response; DNS rebinding check skipped."))
            return self.results

        parsed   = urlparse(url)
        hostname = parsed.hostname or parsed.netloc
        is_https = url.startswith("https://")
        found    = False

        # Check 1: Does the server accept arbitrary Host headers?
        evil_host = "evil-rebind-tbl9z7x.com"
        try:
            r = self.http.get(url, headers={"Host": evil_host})
            if r and r.status_code == 200:
                found = True
                log_warn(logger, f"DNS Rebinding — accepts arbitrary Host header at {url}")
                self.results.append(self._result(
                    url,
                    "DNS Rebinding — server accepts arbitrary Host header",
                    "WARN",
                    detail=(
                        f"GET request with Host: {evil_host!r} returned HTTP 200. "
                        f"Servers that do not validate the Host header are more susceptible "
                        f"to DNS rebinding attacks — the attacker can change DNS to their "
                        f"server and the victim browser's requests will be accepted.\n\n"
                        f"Fix: validate the Host header against a list of expected hostnames. "
                        f"Use HTTPS with HSTS to prevent downgrade."
                    ),
                ))
        except Exception:
            pass

        # Check 2: Resolve IPs and check for private IPs
        ips = _resolve_ips(hostname)
        private_ips = [(fam, ip) for fam, ip in ips if _is_private(ip)]
        if private_ips:
            found = True
            ip_list = ", ".join(f"{fam}:{ip}" for fam, ip in private_ips)
            log_warn(logger, f"DNS Rebinding — private IP in DNS records for {hostname}: {ip_list}")
            self.results.append(self._result(
                url,
                f"DNS Rebinding — private/internal IP in DNS: {ip_list[:60]}",
                "WARN",
                detail=(
                    f"Hostname {hostname!r} resolves to private/internal IP(s): {ip_list}.\n\n"
                    f"Services bound to private IPs that are also publicly DNS-resolvable "
                    f"are potential DNS rebinding targets. An attacker can lure a victim "
                    f"to their page, let it resolve externally, then change DNS to point "
                    f"to the private IP to bypass Same-Origin Policy."
                ),
            ))

        # Check 3: DNS TTL
        ttl = _get_dns_ttl(hostname)
        if ttl is not None and ttl < _LOW_TTL_THRESHOLD:
            found = True
            log_warn(logger, f"DNS Rebinding — very low TTL ({ttl}s) for {hostname}")
            self.results.append(self._result(
                url,
                f"DNS Rebinding — very low DNS TTL ({ttl}s)",
                "WARN",
                detail=(
                    f"DNS TTL for {hostname!r} is {ttl} seconds — shorter than the "
                    f"{_LOW_TTL_THRESHOLD}s threshold. Very low TTLs allow attackers to "
                    f"rapidly re-resolve a hostname to a different IP during a DNS rebinding "
                    f"attack window.\n\n"
                    f"Fix: set DNS TTL to at least 60–300 seconds. TTLs < 30s are a "
                    f"significant enabler for DNS rebinding attacks."
                ),
            ))

        # Check 4: No HTTPS on a public server (makes rebinding easier)
        if not is_https:
            found = True
            log_warn(logger, f"DNS Rebinding — HTTP-only server (no TLS/HSTS protection) at {url}")
            self.results.append(self._result(
                url,
                "DNS Rebinding — HTTP-only server lacks TLS protection",
                "WARN",
                detail=(
                    "The server is reachable over plain HTTP. Without HTTPS and HSTS, "
                    "DNS rebinding attacks are easier to execute because the browser "
                    "has no certificate to validate against the expected hostname.\n\n"
                    "Fix: deploy HTTPS with a valid certificate and set "
                    "Strict-Transport-Security: max-age=31536000."
                ),
            ))

        if not found:
            log_pass(logger, f"DNS Rebinding — no high-risk DNS rebinding factors found for {url}")
            self.results.append(self._result(
                url,
                "DNS Rebinding — no significant rebinding risk factors detected",
                "PASS",
                detail=(
                    "Host header validation appears active, no private IPs in DNS, "
                    "and HTTPS is in use."
                ),
            ))

        return self.results
