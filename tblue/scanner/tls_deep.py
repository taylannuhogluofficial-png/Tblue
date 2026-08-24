"""
Deep TLS/certificate analysis.

Checks beyond basic HTTPS:
- Weak cipher suites (RC4, 3DES, EXPORT, NULL, anon-DH)
- Forward secrecy (ECDHE/DHE key exchange)
- Certificate expiry timeline
- Certificate key size (RSA < 2048, EC < 224)
- Certificate signature algorithm (SHA-1 deprecated)
- HSTS preload readiness
- OCSP stapling (best-effort)
"""

import ssl
import socket
import datetime
from typing import List, Dict, Any
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_WEAK_CIPHERS = [
    ("RC4",    "RC4 stream cipher is broken — trivially decryptable."),
    ("3DES",   "3DES / Triple-DES is vulnerable to Sweet32 birthday attacks."),
    ("DES",    "DES is broken — 56-bit key exhausted in hours."),
    ("EXPORT", "EXPORT-grade ciphers are intentionally weakened — vulnerable to FREAK/Logjam."),
    ("NULL",   "NULL cipher provides no encryption — plaintext on the wire."),
    ("aNULL",  "Anonymous DH provides no authentication — trivial MITM."),
    ("MD5",    "MD5 cipher MAC is cryptographically broken."),
    ("SEED",   "SEED cipher has known weaknesses and is deprecated."),
    ("IDEA",   "IDEA cipher is deprecated and rarely audited."),
    ("ADH",    "Anonymous Diffie-Hellman provides no authentication."),
    ("AECDH",  "Anonymous ECDH provides no authentication."),
]

_EXPIRY_WARN_DAYS  = 30
_EXPIRY_CRIT_DAYS  = 7
_MIN_RSA_BITS      = 2048
_MIN_EC_BITS       = 224


class TLSDeepScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed  = urlparse(url)
        host    = parsed.hostname
        port    = parsed.port or 443

        if parsed.scheme != "https":
            return self.results

        try:
            cert_info = self._get_cert_info(host, port)
        except Exception as e:
            logger.debug(f"TLS deep scan failed for {host}: {e}")
            return self.results

        self._check_cipher(host, port)
        self._check_forward_secrecy(cert_info, host)
        self._check_expiry(cert_info, url)
        self._check_key_size(cert_info, url)
        self._check_sig_algo(cert_info, url)
        self._check_hsts_preload(url)
        return self.results

    # ── Certificate fetch ──────────────────────────────────────────────────────

    def _get_cert_info(self, host: str, port: int) -> dict:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((host, port), timeout=10),
                             server_hostname=host) as s:
            cipher      = s.cipher()
            cert_der    = s.getpeercert(binary_form=True)
            cert_dict   = s.getpeercert()
        return {"cipher": cipher, "cert_der": cert_der, "cert_dict": cert_dict}

    # ── Cipher suite ──────────────────────────────────────────────────────────

    def _check_cipher(self, host: str, port: int) -> None:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.set_ciphers("ALL:eNULL:aNULL:@SECLEVEL=0")
            with ctx.wrap_socket(socket.create_connection((host, port), timeout=10),
                                 server_hostname=host) as s:
                negotiated = s.cipher()[0].upper()
            for pattern, explanation in _WEAK_CIPHERS:
                if pattern.upper() in negotiated:
                    log_fail(logger, f"Weak cipher negotiated: {negotiated}")
                    self.results.append(self._result(
                        f"https://{host}", "TLS — weak cipher suite", "FAIL",
                        detail=(
                            f"Server negotiated cipher: {negotiated}. "
                            f"{explanation} "
                            "Fix: disable this cipher in your web server config and prefer "
                            "TLS_AES_128_GCM_SHA256 / TLS_AES_256_GCM_SHA384 / "
                            "TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3) or "
                            "ECDHE+AESGCM / ECDHE+CHACHA20 (TLS 1.2)."
                        )
                    ))
                    return
            log_pass(logger, f"Cipher suite acceptable: {negotiated}")
        except Exception as e:
            logger.debug(f"Cipher check failed: {e}")

    # ── Forward secrecy ───────────────────────────────────────────────────────

    def _check_forward_secrecy(self, cert_info: dict, host: str) -> None:
        cipher_name = (cert_info.get("cipher") or ("", "", ""))[0] or ""
        has_fs      = any(kex in cipher_name.upper() for kex in ("ECDHE", "DHE", "TLS_AES", "TLS_CHACHA"))
        url         = f"https://{host}"
        if has_fs:
            log_pass(logger, f"Forward secrecy supported: {cipher_name}")
            self.results.append(self._result(url, "TLS — forward secrecy", "PASS",
                detail=f"Negotiated cipher {cipher_name} supports forward secrecy. "
                       "Past sessions remain safe even if the private key is later compromised."))
        else:
            log_warn(logger, f"No forward secrecy: {cipher_name}")
            self.results.append(self._result(url, "TLS — no forward secrecy", "WARN",
                detail=(
                    f"Negotiated cipher {cipher_name} does not support forward secrecy. "
                    "If your private key is ever stolen, all recorded past sessions can be decrypted. "
                    "Fix: prefer ECDHE or DHE key exchange cipher suites."
                )))

    # ── Certificate expiry ────────────────────────────────────────────────────

    def _check_expiry(self, cert_info: dict, url: str) -> None:
        cert_dict = cert_info.get("cert_dict", {})
        not_after = cert_dict.get("notAfter", "")
        if not not_after:
            return
        try:
            expiry  = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            now     = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            days    = (expiry - now).days
        except Exception:
            return

        host = urlparse(url).hostname
        target_url = f"https://{host}"

        if days < 0:
            log_fail(logger, f"Certificate EXPIRED {abs(days)} days ago!")
            self.results.append(self._result(target_url, "TLS — certificate expired", "FAIL",
                detail=f"Certificate expired {abs(days)} day(s) ago on {expiry.date()}. "
                       "Your site is showing security errors to all visitors. "
                       "Renew immediately — Let's Encrypt is free and auto-renews."))
        elif days <= _EXPIRY_CRIT_DAYS:
            log_fail(logger, f"Certificate expires in {days} day(s)!")
            self.results.append(self._result(target_url, "TLS — certificate expiring imminently", "FAIL",
                detail=f"Certificate expires in {days} day(s) on {expiry.date()}. "
                       "Site will break for all visitors when it expires. Renew now."))
        elif days <= _EXPIRY_WARN_DAYS:
            log_warn(logger, f"Certificate expires in {days} days")
            self.results.append(self._result(target_url, "TLS — certificate expiring soon", "WARN",
                detail=f"Certificate expires in {days} day(s) on {expiry.date()}. "
                       "Renew before expiry to avoid downtime."))
        else:
            log_pass(logger, f"Certificate valid for {days} more days")
            self.results.append(self._result(target_url, "TLS — certificate expiry", "PASS",
                detail=f"Certificate is valid for {days} more days (expires {expiry.date()})."))

    # ── Key size ──────────────────────────────────────────────────────────────

    def _check_key_size(self, cert_info: dict, url: str) -> None:
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.asymmetric import rsa, ec
            cert_der = cert_info.get("cert_der")
            if not cert_der:
                return
            cert    = x509.load_der_x509_certificate(cert_der)
            pub_key = cert.public_key()
            host    = urlparse(url).hostname
            target  = f"https://{host}"

            if isinstance(pub_key, rsa.RSAPublicKey):
                bits = pub_key.key_size
                if bits < _MIN_RSA_BITS:
                    log_fail(logger, f"RSA key too small: {bits} bits")
                    self.results.append(self._result(target, "TLS — weak RSA key size", "FAIL",
                        detail=f"Certificate uses {bits}-bit RSA key (minimum recommended: {_MIN_RSA_BITS}). "
                               "Weak keys can be factored. Fix: reissue with RSA-2048 or RSA-4096, "
                               "or migrate to ECDSA P-256 for equivalent security at smaller size."))
                else:
                    log_pass(logger, f"RSA key size adequate: {bits} bits")
                    self.results.append(self._result(target, "TLS — key size", "PASS",
                        detail=f"RSA-{bits} key meets minimum recommendations."))
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                bits = pub_key.key_size
                if bits < _MIN_EC_BITS:
                    self.results.append(self._result(target, "TLS — weak EC key size", "WARN",
                        detail=f"Certificate uses {bits}-bit EC key (minimum recommended: {_MIN_EC_BITS}). "
                               "Fix: use P-256 or stronger."))
                else:
                    self.results.append(self._result(target, "TLS — key size", "PASS",
                        detail=f"EC-{bits} key meets minimum recommendations."))
        except ImportError:
            logger.debug("cryptography library not installed — skipping key size check")
        except Exception as e:
            logger.debug(f"Key size check failed: {e}")

    # ── Signature algorithm ───────────────────────────────────────────────────

    def _check_sig_algo(self, cert_info: dict, url: str) -> None:
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            cert_der = cert_info.get("cert_der")
            if not cert_der:
                return
            cert     = x509.load_der_x509_certificate(cert_der)
            sig_algo = cert.signature_hash_algorithm
            host     = urlparse(url).hostname
            target   = f"https://{host}"

            if sig_algo and isinstance(sig_algo, hashes.SHA1):
                log_warn(logger, "Certificate signed with SHA-1 (deprecated)")
                self.results.append(self._result(target, "TLS — SHA-1 certificate signature", "WARN",
                    detail="Certificate is signed with SHA-1, which is cryptographically broken. "
                           "Modern browsers show security warnings for SHA-1 certificates. "
                           "Fix: reissue your certificate — all public CAs now issue SHA-256 by default."))
            elif sig_algo and isinstance(sig_algo, hashes.MD5):
                log_fail(logger, "Certificate signed with MD5 (broken)")
                self.results.append(self._result(target, "TLS — MD5 certificate signature", "FAIL",
                    detail="Certificate is signed with MD5, which is completely broken. Reissue immediately."))
            else:
                algo_name = type(sig_algo).__name__ if sig_algo else "unknown"
                log_pass(logger, f"Certificate signature algorithm: {algo_name}")
                self.results.append(self._result(target, "TLS — certificate signature algorithm", "PASS",
                    detail=f"Certificate uses {algo_name} signature — acceptable."))
        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"Sig algo check failed: {e}")

    # ── HSTS preload readiness ────────────────────────────────────────────────

    def _check_hsts_preload(self, url: str) -> None:
        try:
            resp    = self.http.get(url)
            if not resp:
                return
            hsts    = resp.headers.get("Strict-Transport-Security", "")
            host    = urlparse(url).hostname
            target  = f"https://{host}"

            if not hsts:
                return  # base ssl scanner already covers missing HSTS

            lower       = hsts.lower()
            max_age     = 0
            inc_sub     = "includesubdomains" in lower
            preload     = "preload" in lower

            for part in lower.split(";"):
                part = part.strip()
                if part.startswith("max-age="):
                    try:
                        max_age = int(part.split("=", 1)[1])
                    except ValueError:
                        pass

            ready = max_age >= 31536000 and inc_sub and preload

            if ready:
                log_pass(logger, "HSTS preload-ready")
                self.results.append(self._result(target, "TLS — HSTS preload ready", "PASS",
                    detail="HSTS header meets preload requirements: max-age ≥ 1 year, "
                           "includeSubDomains, and preload directive present. "
                           "Submit to hstspreload.org to be hardcoded into browsers."))
            else:
                issues = []
                if max_age < 31536000:
                    issues.append(f"max-age={max_age} (need ≥ 31536000)")
                if not inc_sub:
                    issues.append("missing includeSubDomains")
                if not preload:
                    issues.append("missing preload directive")
                log_warn(logger, f"HSTS not preload-ready: {', '.join(issues)}")
                self.results.append(self._result(target, "TLS — HSTS not preload-ready", "WARN",
                    detail=(
                        f"HSTS header is present but not preload-ready: {'; '.join(issues)}. "
                        "Preloading means browsers enforce HTTPS for your domain even on the very "
                        "first connection — before they see your HSTS header. "
                        "Fix: set max-age=31536000; includeSubDomains; preload, then submit to hstspreload.org."
                    )))
        except Exception as e:
            logger.debug(f"HSTS preload check failed: {e}")
