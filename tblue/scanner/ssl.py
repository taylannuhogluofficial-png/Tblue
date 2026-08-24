"""
SSL / HTTPS scanner.
Checks HTTPS, HTTP redirect, certificate expiry, and TLS version.
"""

import ssl
import socket
from datetime import datetime, timezone
from typing import List, Dict, Any
from urllib.parse import urlparse
from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

EXPIRY_WARN_DAYS = 30   # warn if cert expires within 30 days
EXPIRY_FAIL_DAYS = 7    # fail if cert expires within 7 days


class SSLScanner(BaseScanner):
    """
    Checks SSL/HTTPS configuration including:
    - HTTPS enforcement
    - HTTP to HTTPS redirect
    - Certificate expiry
    - TLS version support
    """

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed   = urlparse(url)
        is_https = parsed.scheme == "https"
        hostname = parsed.netloc.split(":")[0]

        if is_https:
            log_pass(logger, f"HTTPS enabled on {url}")
            self.results.append(self._result(
                url, "SSL / HTTPS", "PASS",
                detail="Site is using HTTPS — traffic is encrypted."
            ))
            self._check_http_redirect(url)
            self._check_cert_expiry(hostname)
            self._check_cert_details(hostname)
            self._check_tls_version(hostname)
        else:
            log_fail(logger, f"No HTTPS on {url}")
            self.results.append(self._result(
                url, "SSL / HTTPS", "FAIL",
                detail=(
                    "Site is using HTTP only — all traffic is unencrypted. "
                    "Fix: enable HTTPS and redirect all HTTP traffic to HTTPS."
                )
            ))

        return self.results

    def _check_http_redirect(self, https_url: str) -> None:
        """Check if HTTP version redirects to HTTPS."""
        http_url = https_url.replace("https://", "http://", 1)
        resp     = self.http.get(http_url, allow_redirects=True)
        if not resp:
            return
        if resp.url.startswith("https://"):
            log_pass(logger, f"HTTP → HTTPS redirect confirmed")
            self.results.append(self._result(
                http_url, "HTTP → HTTPS redirect", "PASS",
                detail="HTTP traffic is automatically redirected to HTTPS."
            ))
        else:
            log_fail(logger, f"HTTP does not redirect to HTTPS")
            self.results.append(self._result(
                http_url, "HTTP → HTTPS redirect", "FAIL",
                detail="HTTP version does not redirect to HTTPS. Fix: add a server-level redirect."
            ))

    def _check_cert_expiry(self, hostname: str) -> None:
        """Check SSL certificate expiry date."""
        try:
            ctx  = ssl.create_default_context()
            conn = ctx.wrap_socket(
                socket.create_connection((hostname, 443), timeout=self.http.timeout),
                server_hostname=hostname,
            )
            cert      = conn.getpeercert()
            conn.close()

            expires_str = cert.get("notAfter", "")
            if not expires_str:
                return

            expires = datetime.strptime(expires_str, "%b %d %H:%M:%S %Y %Z")
            expires = expires.replace(tzinfo=timezone.utc)
            now     = datetime.now(tz=timezone.utc)
            days    = (expires - now).days

            if days <= EXPIRY_FAIL_DAYS:
                log_fail(logger, f"SSL cert expires in {days} days — CRITICAL")
                self.results.append(self._result(
                    f"https://{hostname}", "SSL — certificate expiry", "FAIL",
                    detail=f"Certificate expires in {days} days on {expires_str}. Renew immediately."
                ))
            elif days <= EXPIRY_WARN_DAYS:
                log_warn(logger, f"SSL cert expires in {days} days")
                self.results.append(self._result(
                    f"https://{hostname}", "SSL — certificate expiry", "WARN",
                    detail=f"Certificate expires in {days} days on {expires_str}. Renew soon."
                ))
            else:
                log_pass(logger, f"SSL cert valid for {days} days")
                self.results.append(self._result(
                    f"https://{hostname}", "SSL — certificate expiry", "PASS",
                    detail=f"Certificate valid for {days} more days (expires {expires_str})."
                ))

        except Exception as e:
            log_warn(logger, f"Could not check cert expiry for {hostname} — {e}")

    def _check_cert_details(self, hostname: str) -> None:
        """Check certificate: self-signed detection, SANs coverage, chain validity."""
        try:
            ctx                = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            conn = ctx.wrap_socket(
                socket.create_connection((hostname, 443), timeout=self.http.timeout),
                server_hostname=hostname,
            )
            cert = conn.getpeercert()
            conn.close()

            if not cert:
                return

            issuer  = dict(x[0] for x in cert.get("issuer", []))
            subject = dict(x[0] for x in cert.get("subject", []))

            # Self-signed: issuer CN == subject CN
            if issuer.get("commonName") and issuer.get("commonName") == subject.get("commonName"):
                log_fail(logger, f"Self-signed certificate detected on {hostname}")
                self.results.append(self._result(
                    f"https://{hostname}", "SSL — self-signed certificate", "FAIL",
                    detail=(
                        "Certificate is self-signed (issuer equals subject). "
                        "Browsers will show security warnings and users may bypass them, "
                        "leaving them vulnerable to MITM attacks. "
                        "Fix: obtain a certificate from a trusted CA (Let's Encrypt is free)."
                    )
                ))
            else:
                log_pass(logger, f"Certificate is CA-signed on {hostname}")
                self.results.append(self._result(
                    f"https://{hostname}", "SSL — certificate authority", "PASS",
                    detail=f"Certificate issued by: {issuer.get('organizationName', issuer.get('commonName', 'unknown'))}."
                ))

            # SANs coverage
            sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
            if not sans:
                log_warn(logger, f"No SANs in certificate for {hostname}")
                self.results.append(self._result(
                    f"https://{hostname}", "SSL — no Subject Alternative Names", "WARN",
                    detail=(
                        "Certificate has no Subject Alternative Names (SANs). "
                        "Modern browsers require SANs and ignore the CN field. "
                        "Fix: reissue the certificate with SANs covering all hostnames served."
                    )
                ))
            else:
                covered = any(
                    hostname == san or (san.startswith("*.") and hostname.endswith(san[1:]))
                    for san in sans
                )
                if covered:
                    log_pass(logger, f"Certificate SANs cover {hostname}")
                    self.results.append(self._result(
                        f"https://{hostname}", "SSL — SANs coverage", "PASS",
                        detail=f"Certificate covers hostname via SANs: {', '.join(sans[:5])}."
                    ))
                else:
                    log_fail(logger, f"Certificate SANs do not cover {hostname}")
                    self.results.append(self._result(
                        f"https://{hostname}", "SSL — SANs mismatch", "FAIL",
                        detail=(
                            f"Certificate SANs ({', '.join(sans[:5])}) do not cover '{hostname}'. "
                            "Browsers will show a certificate mismatch error. "
                            "Fix: reissue the certificate with the correct hostname in SANs."
                        )
                    ))

        except ssl.SSLCertVerificationError as e:
            log_fail(logger, f"Certificate chain validation failed for {hostname}: {e}")
            self.results.append(self._result(
                f"https://{hostname}", "SSL — certificate chain invalid", "FAIL",
                detail=(
                    f"Certificate chain validation failed: {e}. "
                    "This may indicate missing intermediate certificates. "
                    "Fix: configure your server to send the full certificate chain "
                    "(leaf cert + all intermediate CA certs)."
                )
            ))
        except Exception as e:
            log_warn(logger, f"Could not check cert details for {hostname} — {e}")

    def _check_tls_version(self, hostname: str) -> None:
        """Check if outdated TLS versions are accepted."""
        outdated = []

        for version, label in [
            (ssl.TLSVersion.TLSv1,   "TLS 1.0"),
            (ssl.TLSVersion.TLSv1_1, "TLS 1.1"),
        ]:
            try:
                ctx             = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                ctx.minimum_version = version
                ctx.maximum_version = version
                conn = ctx.wrap_socket(
                    socket.create_connection((hostname, 443), timeout=self.http.timeout),
                    server_hostname=hostname,
                )
                conn.close()
                outdated.append(label)
            except Exception:
                pass  # version rejected — good

        if outdated:
            log_fail(logger, f"Outdated TLS versions accepted: {', '.join(outdated)}")
            self.results.append(self._result(
                f"https://{hostname}", "SSL — TLS version", "FAIL",
                detail=(
                    f"Outdated TLS versions accepted: {', '.join(outdated)}. "
                    "Fix: disable TLS 1.0 and 1.1 — only allow TLS 1.2 and 1.3."
                )
            ))
        else:
            log_pass(logger, f"Only modern TLS versions accepted on {hostname}")
            self.results.append(self._result(
                f"https://{hostname}", "SSL — TLS version", "PASS",
                detail="TLS 1.0 and 1.1 are disabled — only modern TLS versions accepted."
            ))
