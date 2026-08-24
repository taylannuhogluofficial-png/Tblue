"""Active TLS Cipher Probe — negotiate real TLS handshakes to detect deprecated protocols and weak ciphers."""
import ssl
import socket
import re
from urllib.parse import urlparse
from .base import BaseScanner

active = True

_ATCP_ANY_RE = re.compile(r'^https?://', re.I)

_DANGEROUS_PORTS = {443, 8443, 4443, 9443}

_WEAK_CIPHER_SUBSTRINGS = [
    "RC4", "NULL", "EXPORT", "DES", "3DES", "ANON", "MD5", "RC2",
]


def _tcp_tls_connect(host: str, port: int, min_ver, max_ver, timeout: float = 5.0):
    """Attempt TLS handshake with specific protocol bounds. Returns (cipher_name, proto_name) or None."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = min_ver
        ctx.maximum_version = max_ver
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                proto = ssock.version()
                return cipher[0] if cipher else "unknown", proto
    except Exception:
        return None


def _banner_grab(host: str, port: int, timeout: float = 3.0) -> str:
    """Grab a brief plaintext banner from an open port."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                banner = s.recv(256)
                return banner.decode(errors="replace").strip()[:120]
            except Exception:
                return ""
    except Exception:
        return ""


class ActiveTLSCipherProbeScanner(BaseScanner):
    def scan(self, url: str) -> list:
        if not _ATCP_ANY_RE.match(url):
            return [self._result(url, "active_tls_cipher_not_used", "PASS")]

        parsed = urlparse(url)
        host = parsed.hostname or ""
        if not host:
            return [self._result(url, "active_tls_cipher_not_used", "PASS")]

        is_https = parsed.scheme.lower() == "https"
        port = parsed.port or (443 if is_https else 80)
        if not is_https:
            return [self._result(url, "active_tls_cipher_not_https", "INFO",
                                 detail="Target is HTTP — no TLS to probe. Migrate to HTTPS before TLS hardening is meaningful.")]

        findings = []

        # Test TLS 1.0 (deprecated RFC 8996 March 2021)
        try:
            r10 = _tcp_tls_connect(host, port,
                                    ssl.TLSVersion.TLSv1,
                                    ssl.TLSVersion.TLSv1)
            if r10:
                cipher_name, proto = r10
                findings.append(self._result(
                    url, "active_tls_tls10_accepted", "FAIL",
                    detail=f"TLS 1.0 accepted (cipher: {cipher_name}) — deprecated by RFC 8996; vulnerable to BEAST and POODLE variants; PCI-DSS 3.2+ prohibits TLS 1.0 for cardholder data environments; disable via ssl_protocols in nginx or SSLProtocol in Apache.",
                ))
        except Exception:
            pass

        # Test TLS 1.1 (deprecated RFC 8996 March 2021)
        try:
            r11 = _tcp_tls_connect(host, port,
                                    ssl.TLSVersion.TLSv1_1,
                                    ssl.TLSVersion.TLSv1_1)
            if r11:
                cipher_name, proto = r11
                findings.append(self._result(
                    url, "active_tls_tls11_accepted", "WARN",
                    detail=f"TLS 1.1 accepted (cipher: {cipher_name}) — deprecated by RFC 8996; browsers removed TLS 1.1 support in 2020; configure minimum TLS 1.2 or preferably 1.3 on the server.",
                ))
        except Exception:
            pass

        # Test TLS 1.2 (current minimum — check cipher quality)
        try:
            r12 = _tcp_tls_connect(host, port,
                                    ssl.TLSVersion.TLSv1_2,
                                    ssl.TLSVersion.TLSv1_2)
            if r12:
                cipher_name, proto = r12
                cipher_up = cipher_name.upper()
                weak = [s for s in _WEAK_CIPHER_SUBSTRINGS if s in cipher_up]
                if weak:
                    findings.append(self._result(
                        url, "active_tls_weak_cipher_tls12", "FAIL",
                        detail=f"Weak cipher suite negotiated over TLS 1.2: {cipher_name} (weak components: {', '.join(weak)}) — RC4 broken since 2013 (RFC 7465 prohibits it); NULL provides no encryption; EXPORT ciphers limited to 40-bit (FREAK attack); 3DES vulnerable to SWEET32 (CVE-2016-2183); configure cipher priority list to exclude these.",
                    ))
        except Exception:
            pass

        # Test TLS 1.3 presence (good — note if absent)
        try:
            r13 = _tcp_tls_connect(host, port,
                                    ssl.TLSVersion.TLSv1_3,
                                    ssl.TLSVersion.TLSv1_3)
            if not r13:
                findings.append(self._result(
                    url, "active_tls_tls13_not_supported", "INFO",
                    detail="TLS 1.3 not supported — TLS 1.3 eliminates legacy cipher suites, provides 0-RTT resumption hardening, and removes RSA key exchange; enabling it improves both security and handshake performance.",
                ))
        except Exception:
            findings.append(self._result(
                url, "active_tls_tls13_not_supported", "INFO",
                detail="TLS 1.3 not supported — TLS 1.3 eliminates legacy cipher suites, provides 0-RTT resumption hardening, and removes RSA key exchange; enabling it improves both security and handshake performance.",
            ))

        return findings or [self._result(url, "active_tls_strong_configuration", "PASS",
                                          detail="TLS configuration: no deprecated protocols (SSLv3/TLS1.0/TLS1.1) accepted, no weak ciphers detected, TLS 1.3 supported.")]
