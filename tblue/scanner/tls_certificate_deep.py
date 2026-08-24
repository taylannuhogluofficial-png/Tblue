"""TLS certificate deep — cipher weakness, self-signed, expired, cert chain via HTTPS headers."""
import re
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from .base import BaseScanner

_WEAK_CIPHER_RE = re.compile(
    r'\b(RC4|DES|3DES|EXPORT|NULL|ANON|MD5|SHA1(?!28|56)|ADH|AECDH)\b', re.I
)

_HSTS_MIN_AGE = 15_552_000  # 180 days in seconds
_HSTS_MAX_AGE_RE = re.compile(r'max-age=(\d+)', re.I)


def _get_cert_info(hostname: str, port: int = 443) -> dict:
    """Retrieve certificate metadata via ssl.get_server_certificate + SSLContext."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_OPTIONAL
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()  # (name, version, bits)
                cert = ssock.getpeercert()
                return {"cipher": cipher, "cert": cert, "error": None}
    except Exception as exc:
        return {"cipher": None, "cert": None, "error": str(exc)}


def _check_cipher(cipher_name: str, url: str) -> list:
    findings = []
    if _WEAK_CIPHER_RE.search(cipher_name):
        findings.append({
            "type": "tls_weak_cipher",
            "status": "FAIL",
            "url": url,
            "detail": f"Weak cipher negotiated: {cipher_name}",
        })
    return findings


def _check_cert_validity(cert: dict, url: str) -> list:
    findings = []
    if not cert:
        findings.append({
            "type": "tls_no_cert",
            "status": "FAIL",
            "url": url,
            "detail": "No certificate returned — possible self-signed or TLS failure",
        })
        return findings

    not_after = cert.get("notAfter")
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (exp - now).days
            if days_left < 0:
                findings.append({
                    "type": "tls_cert_expired",
                    "status": "FAIL",
                    "url": url,
                    "detail": f"TLS certificate expired {abs(days_left)} days ago ({not_after})",
                })
            elif days_left < 14:
                findings.append({
                    "type": "tls_cert_expiring_soon",
                    "status": "WARN",
                    "url": url,
                    "detail": f"TLS certificate expires in {days_left} days ({not_after})",
                })
        except (ValueError, TypeError):
            pass

    # Check SAN/CN presence
    san = cert.get("subjectAltName", [])
    subject = dict(x[0] for x in cert.get("subject", []))
    if not san and not subject.get("commonName"):
        findings.append({
            "type": "tls_no_san",
            "status": "WARN",
            "url": url,
            "detail": "Certificate has no SAN extension — browser may reject it",
        })
    return findings


def _check_hsts_header(headers: dict, url: str) -> list:
    findings = []
    hsts = headers.get("strict-transport-security", "")
    if not hsts:
        return findings  # missing HSTS is handled by other scanners

    m = _HSTS_MAX_AGE_RE.search(hsts)
    if m:
        age = int(m.group(1))
        if age < _HSTS_MIN_AGE:
            findings.append({
                "type": "tls_hsts_short_maxage",
                "status": "WARN",
                "url": url,
                "detail": f"HSTS max-age too short: {age}s (min recommended {_HSTS_MIN_AGE}s / 180 days)",
            })
    return findings


class TLSCertificateDeepScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        parsed = urlparse(url)

        # Only meaningful on HTTPS targets
        if parsed.scheme != "https":
            return [self._result(url, "tls_cert_not_https", "PASS",
                                 detail="Target is not HTTPS — TLS checks skipped")]

        hostname = parsed.hostname
        port = parsed.port or 443

        info = _get_cert_info(hostname, port)
        if info["error"] and not info["cert"] and not info["cipher"]:
            return [self._result(url, "tls_cert_connect_error", "WARN",
                                 detail=f"TLS connect error: {info['error'][:120]}")]

        if info["cipher"]:
            cipher_name = info["cipher"][0]
            for f in _check_cipher(cipher_name, url):
                results.append(self._result(f["url"], f["type"], f["status"],
                                            detail=f["detail"]))

        for f in _check_cert_validity(info["cert"], url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        resp = self.http.get(url)
        if resp:
            for f in _check_hsts_header(dict(resp.headers), url):
                results.append(self._result(f["url"], f["type"], f["status"],
                                            detail=f["detail"]))

        if not results:
            results.append(self._result(url, "tls_cert_ok", "PASS",
                                        detail="TLS certificate and cipher configuration looks healthy"))
        return results
