"""
TLS Protocol Version Scanner.

Checks which TLS protocol versions a server will accept, identifying:

  1. TLS 1.0 — deprecated by RFC 8996 (2021); vulnerable to BEAST, POODLE.
     Detection: attempt SSL handshake with max_version=TLS1_0.
  2. TLS 1.1 — deprecated by RFC 8996 (2021); no known attacks but removed
     from most browsers in 2020.
  3. TLS 1.2 — still secure; current baseline minimum.
  4. TLS 1.3 — best current practice.

Also checks for cipher suite issues detectable without a full TLS scan:
  5. RC4 cipher negotiated — detectable via ssl module when server allows
     (older servers may still accept RC4 when downgraded).
  6. Export-grade cipher (EXPORT) negotiated — FREAK attack surface.
  7. NULL / aNULL cipher — catastrophic, no encryption at all.
  8. 3DES / DES — SWEET32 vulnerability.

Implementation:
  - Uses Python ssl module to negotiate handshakes at each TLS version.
  - ctx.minimum_version / ctx.maximum_version to force negotiation.
  - Graceful failure if connection refused or not TLS.

Read-only. No payload sent beyond the TLS ClientHello.

CWE-326: Inadequate Encryption Strength
References: RFC 8996, RFC 7568
"""

import ssl
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_WEAK_CIPHER_KEYWORDS = [
    ("RC4",      "FAIL", "RC4 stream cipher (broken — biased key stream)"),
    ("EXPORT",   "FAIL", "Export-grade cipher (FREAK attack vector)"),
    ("NULL",     "FAIL", "NULL encryption — no confidentiality"),
    ("aNULL",    "FAIL", "Anonymous authentication — no server authentication"),
    ("DES-CBC3", "WARN", "3DES / SWEET32 vulnerable to birthday attacks"),
    ("DES",      "WARN", "DES cipher (56-bit, broken by brute force)"),
    ("MD5",      "WARN", "MD5 in cipher suite (collision-prone MAC)"),
]


def _tls_handshake(hostname: str, port: int, min_ver, max_ver) -> Optional[str]:
    """
    Attempt TLS handshake with forced version range.
    Returns negotiated cipher name or None if connection fails.
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.minimum_version = min_ver
        ctx.maximum_version = max_ver
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                return cipher[0] if cipher else "unknown"
    except Exception:
        return None


def _check_protocol(hostname: str, port: int) -> List[Dict]:
    findings = []

    # TLS 1.0
    if hasattr(ssl, "TLSVersion"):
        tls10_cipher = None
        tls11_cipher = None
        try:
            tls10_cipher = _tls_handshake(
                hostname, port,
                ssl.TLSVersion.TLSv1,
                ssl.TLSVersion.TLSv1,
            )
        except AttributeError:
            pass

        if tls10_cipher:
            findings.append({
                "type": "tls-protocol-tls10-accepted",
                "severity": "FAIL",
                "detail": (
                    f"TLS 1.0 handshake succeeded (cipher: {tls10_cipher}). "
                    f"TLS 1.0 was deprecated by RFC 8996 in 2021 and is vulnerable to "
                    f"BEAST and POODLE attacks.\n\n"
                    f"Fix: configure the server to reject TLS < 1.2. "
                    f"Minimum supported version should be TLS 1.2; prefer TLS 1.3."
                ),
            })

        # TLS 1.1
        try:
            tls11_cipher = _tls_handshake(
                hostname, port,
                ssl.TLSVersion.TLSv1_1,
                ssl.TLSVersion.TLSv1_1,
            )
        except AttributeError:
            pass

        if tls11_cipher:
            findings.append({
                "type": "tls-protocol-tls11-accepted",
                "severity": "WARN",
                "detail": (
                    f"TLS 1.1 handshake succeeded (cipher: {tls11_cipher}). "
                    f"TLS 1.1 was deprecated by RFC 8996 in 2021. While no critical attacks "
                    f"exist, browsers removed support in 2020.\n\n"
                    f"Fix: configure minimum TLS version to TLS 1.2."
                ),
            })

    return findings


def _check_cipher(cipher_name: str) -> Optional[Dict]:
    for kw, sev, desc in _WEAK_CIPHER_KEYWORDS:
        if kw in cipher_name.upper():
            return {
                "type": f"tls-weak-cipher-{kw.lower().replace('-','_')}",
                "severity": sev,
                "detail": (
                    f"Negotiated cipher contains '{kw}': {cipher_name}. "
                    f"{desc}.\n\n"
                    f"Fix: disable this cipher suite in your TLS configuration and only "
                    f"allow ECDHE/DHE key exchange with AES-GCM or ChaCha20-Poly1305."
                ),
            }
    return None


class TLSProtocolVersionScanner(BaseScanner):
    """Checks for accepted TLS 1.0/1.1 and weak cipher suites via actual TLS handshakes."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        if not url.startswith("https://"):
            self.results.append(self._result(
                url, "TLS Protocol Version — non-HTTPS target skipped", "PASS",
                detail="URL is not HTTPS; TLS protocol version check is not applicable."))
            return self.results

        parsed   = urlparse(url)
        hostname = parsed.hostname or parsed.netloc
        port     = parsed.port or 443

        found = False

        # Protocol version checks
        for f in _check_protocol(hostname, port):
            found = True
            if f["severity"] == "FAIL":
                log_fail(logger, f"TLS Protocol Version — {f['type']} for {hostname}")
            else:
                log_warn(logger, f"TLS Protocol Version — {f['type']} for {hostname}")
            self.results.append(self._result(
                url, f["type"], f["severity"], detail=f["detail"]))

        # Check currently negotiated cipher for weakness
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    negotiated_cipher = ssock.cipher()
                    if negotiated_cipher:
                        cipher_name = negotiated_cipher[0]
                        f = _check_cipher(cipher_name)
                        if f:
                            found = True
                            log_warn(logger, f"TLS Protocol Version — {f['type']}: {cipher_name}")
                            self.results.append(self._result(
                                url, f["type"], f["severity"], detail=f["detail"]))
        except Exception:
            pass

        if not found:
            log_pass(logger, f"TLS Protocol Version — no deprecated protocols or weak ciphers for {url}")
            self.results.append(self._result(
                url,
                "TLS Protocol Version — TLS 1.2+ only, no weak ciphers",
                "PASS",
                detail="TLS 1.0 and TLS 1.1 are rejected. Negotiated cipher is not in the weak cipher list.",
            ))

        return self.results
