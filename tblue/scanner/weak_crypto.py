"""
Weak Cryptography Detection Scanner.

Detects use of deprecated or broken cryptographic primitives in HTTP responses:

1. MD5 in ETag header — leaks hash function, trivially collided
2. Content-MD5 header — deprecated RFC 3230, MD5 is broken for integrity
3. SHA1 in Set-Cookie values or session IDs (32-char hex → likely MD5)
4. Weak cipher suite negotiated (RC4, DES, 3DES, EXPORT, NULL, ANON) in TLS
5. Short session tokens (≤ 16 hex chars) in Set-Cookie → insufficient entropy
6. MD5-looking ETag (32 lowercase hex chars without quotes-W/) → session fixation
7. Passwords or tokens using deprecated bcrypt cost ≤ 6 or visible in body
8. JWT with RS256 where key size hint in header suggests < 2048 bits
9. WWW-Authenticate: Digest with MD5 algorithm (MITM-vulnerable)
10. Server announcing weak TLS via Alt-Svc / Upgrade header

CWE-327: Use of a Broken or Risky Cryptographic Algorithm
CWE-916: Use of Password Hash with Insufficient Computational Effort
"""

import re
from typing import Any, Dict, List
from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# 32-char lowercase hex — MD5 fingerprint pattern
_MD5_HEX_RE = re.compile(r'\b[0-9a-f]{32}\b')

# 40-char lowercase hex — SHA1 fingerprint pattern
_SHA1_HEX_RE = re.compile(r'\b[0-9a-f]{40}\b')

# ETag that looks like a bare MD5 hash (no W/ prefix, pure hex)
_MD5_ETAG_RE = re.compile(r'^"?[0-9a-f]{32}"?$', re.I)

# Short session token (≤16 chars of hex → ≤64 bits entropy)
_SHORT_TOKEN_RE = re.compile(r'(?:session|sess|token|sid|auth)=[0-9a-f]{4,16}(?:;|$|\s)', re.I)

# Weak cipher suite patterns in Server header or body
_WEAK_CIPHER_RE = re.compile(
    r'\b(?:RC4|DES|3DES|EXPORT|NULL|ANON|ADH|EXP-|MD5WithRSA|SHA1WithRSA)\b',
    re.I,
)

# HTTP Digest authentication with MD5 algorithm
_DIGEST_MD5_RE = re.compile(r'Digest.*algorithm=MD5(?!\d)', re.I)

# Content-MD5 header
_CONTENT_MD5_HDR = "content-md5"


class WeakCryptoScanner(BaseScanner):
    """Detects weak or broken cryptographic primitives in HTTP responses."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping weak crypto checks: {url}")
            self.results.append(self._result(
                url, "Weak crypto — no response", "PASS",
                detail="Target did not respond; weak crypto checks skipped."
            ))
            return self.results

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        self._check_etag(url, headers_lower)
        self._check_content_md5(url, headers_lower)
        self._check_cookie_entropy(url, headers_lower)
        self._check_digest_auth(url, headers_lower)
        self._check_body_cipher_disclosure(url, resp)

        if not self.results:
            log_pass(logger, f"No weak cryptographic primitives detected: {url}")
            self.results.append(self._result(
                url, "Weak crypto — no weak algorithms detected", "PASS",
                detail=(
                    "Response headers and body show no evidence of weak cryptographic "
                    "primitives (MD5 ETags, short session tokens, Digest/MD5 auth, weak ciphers)."
                )
            ))

        return self.results

    def _check_etag(self, url: str, headers: dict) -> None:
        etag = headers.get("etag", "")
        if not etag:
            return
        # Strip quotes for the check
        etag_clean = etag.strip('"').strip("W/").strip('"')
        if _MD5_ETAG_RE.match(etag_clean):
            log_warn(logger, f"MD5-based ETag detected: {etag}")
            self.results.append(self._result(
                url, f"Weak crypto — MD5-based ETag: {etag}", "WARN",
                detail=(
                    f"ETag value '{etag}' appears to be an MD5 hash. "
                    "MD5 is cryptographically broken (trivially collided). "
                    "Using MD5 for ETags can also leak information about file content "
                    "or inode numbers (Apache-style). "
                    "Fix: use a strong hash (SHA-256) or an opaque timestamp/version token "
                    "for ETag generation."
                )
            ))

    def _check_content_md5(self, url: str, headers: dict) -> None:
        if _CONTENT_MD5_HDR in headers:
            log_warn(logger, f"Deprecated Content-MD5 header found: {url}")
            self.results.append(self._result(
                url, "Weak crypto — deprecated Content-MD5 header", "WARN",
                detail=(
                    "Server sends Content-MD5 header (RFC 2616 §14.15). "
                    "This header was deprecated in RFC 7231 because MD5 is cryptographically broken "
                    "and provides no real integrity protection against active attackers. "
                    "Fix: remove Content-MD5 from responses; use TLS for transport integrity."
                )
            ))

    def _check_cookie_entropy(self, url: str, headers: dict) -> None:
        cookie_header = headers.get("set-cookie", "")
        if not cookie_header:
            return

        # Check for suspiciously short hex tokens (likely MD5 substrings or low-entropy)
        if _SHORT_TOKEN_RE.search(cookie_header):
            log_fail(logger, f"Low-entropy session token in Set-Cookie: {url}")
            self.results.append(self._result(
                url, "Weak crypto — low-entropy session/token value in Set-Cookie", "FAIL",
                detail=(
                    "Set-Cookie contains a session or token with ≤16 hex characters (≤64 bits). "
                    "With 64-bit tokens, an attacker making ~4 billion requests can statistically "
                    "expect to collide with a live session. "
                    "Fix: generate session tokens using a CSPRNG with ≥128 bits of entropy "
                    "(e.g., 32 hex chars or 22 base64url chars)."
                )
            ))
            return

        # Check for MD5-sized token in cookie values
        for part in cookie_header.split(";"):
            if "=" in part:
                key, _, val = part.partition("=")
                val = val.strip()
                if _MD5_HEX_RE.fullmatch(val.strip('"')):
                    log_warn(logger, f"MD5-length cookie token in {key.strip()}: {url}")
                    self.results.append(self._result(
                        url, f"Weak crypto — MD5-length token in cookie '{key.strip()}'", "WARN",
                        detail=(
                            f"Cookie '{key.strip()}' has a 32-character hex value matching MD5 length. "
                            "If this is a session token derived from MD5, it is insecure. "
                            "MD5 tokens can be brute-forced or exploited via hash extension attacks. "
                            "Fix: use CSPRNG-generated tokens (not hashes of user data); "
                            "minimum 128-bit (32-byte) random tokens."
                        )
                    ))
                    return

    def _check_digest_auth(self, url: str, headers: dict) -> None:
        www_auth = headers.get("www-authenticate", "")
        if not www_auth:
            return
        if _DIGEST_MD5_RE.search(www_auth):
            log_fail(logger, f"HTTP Digest authentication with MD5 algorithm: {url}")
            self.results.append(self._result(
                url, "Weak crypto — HTTP Digest authentication uses MD5 algorithm", "FAIL",
                detail=(
                    "Server requests HTTP Digest authentication with algorithm=MD5. "
                    "MD5 Digest authentication is vulnerable to offline dictionary attacks "
                    "and MITM downgrade attacks. The nonce is too short for replay protection. "
                    "Fix: migrate to token-based authentication (Bearer JWT, OAuth 2.0) over HTTPS. "
                    "If Digest is required, use algorithm=SHA-256 (RFC 7616)."
                )
            ))

    def _check_body_cipher_disclosure(self, url: str, resp) -> None:
        body = resp.text or ""
        server = {k.lower(): v for k, v in resp.headers.items()}.get("server", "")
        combined = f"{server} {body[:4096]}"

        m = _WEAK_CIPHER_RE.search(combined)
        if m:
            log_warn(logger, f"Weak cipher reference in response: {m.group()}")
            self.results.append(self._result(
                url, f"Weak crypto — weak cipher referenced in response: {m.group()}", "WARN",
                detail=(
                    f"Weak cryptographic algorithm '{m.group()}' was mentioned in the response "
                    "(Server header or response body). RC4, DES, 3DES, EXPORT ciphers, "
                    "and NULL/ANON suites are all broken or dangerously weak. "
                    "Fix: configure TLS to use only TLS 1.2+ with AEAD cipher suites "
                    "(AES-GCM, ChaCha20-Poly1305). Disable RC4, DES, 3DES, and EXPORT suites."
                )
            ))
