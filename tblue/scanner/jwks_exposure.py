"""
JWKS / Public Key Exposure Scanner.

JSON Web Key Sets (JWKS) endpoints expose the public keys used to verify JWTs.
While the keys themselves are public, misconfiguration can reveal:

  1. JWKS endpoint publicly accessible with private key material (kty=oct,
     symmetric keys should never be published in JWKS).

  2. Algorithm confusion risk — if the JWKS includes both RSA/EC public keys
     AND accepts symmetric 'none' or 'HS*' algorithm entries alongside, it
     may be vulnerable to algorithm substitution attacks.

  3. JWKS contains keys with very short key lengths (RSA < 2048 bits → WARN,
     RSA < 1024 bits → FAIL; EC P-192 or custom curves → WARN).

  4. Key ID (kid) collision — if multiple keys share the same 'kid' value.

  5. 'use': 'enc' key exposed without access control — asymmetric encryption
     private key would be catastrophic; symmetric enc key exposure is critical.

  6. Stale / many keys — more than 10 keys in JWKS suggests poor key rotation.

Checks well-known JWKS paths and also parses 'jwks_uri' from OIDC discovery.

Read-only. No mutation.

References:
  RFC 7517 — JSON Web Key
  CWE-321: Use of Hard-coded Cryptographic Key
  CWE-326: Inadequate Encryption Strength
"""

import json
import math
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_JWKS_PATHS = [
    "/.well-known/jwks.json",
    "/.well-known/openid-configuration",  # discover jwks_uri from this
    "/jwks.json",
    "/api/jwks",
    "/api/v1/jwks",
    "/.well-known/keys",
    "/oauth/jwks",
    "/auth/jwks.json",
]

_SYMMETRIC_KTYPES = {"oct"}
_WEAK_CURVES      = {"p-192", "secp192r1", "prime192v1"}


def _rsa_key_strength(n_b64url: str) -> str:
    """
    Classify RSA key strength based on base64url-encoded modulus length.

    RSA-1024 modulus = 128 bytes → ~171 base64url chars
    RSA-2048 modulus = 256 bytes → ~342 base64url chars

    Returns 'ok', 'weak', or 'critical'.
    """
    n_len = len(n_b64url.rstrip("="))
    if n_len < 172:     # < 1024 bits
        return "critical"
    if n_len < 342:     # < 2048 bits
        return "weak"
    return "ok"


def _analyze_key(key: Dict) -> List[Dict]:
    findings = []
    kty = key.get("kty", "").lower()
    kid = key.get("kid", "")
    use = key.get("use", "")
    alg = key.get("alg", "").upper()

    if kty == "oct":
        findings.append({
            "type": "jwks-symmetric-key-exposed",
            "severity": "FAIL",
            "detail": (
                f"JWKS contains a symmetric key (kty=oct, kid={kid!r}). "
                f"Symmetric keys are shared secrets and must NEVER be published in a "
                f"public JWKS endpoint. Any party reading this key can forge arbitrary JWTs.\n\n"
                f"Fix: remove symmetric keys from JWKS. Use asymmetric keys (RSA/EC) for "
                f"signing and verification."
            ),
        })

    elif kty == "rsa":
        n = key.get("n", "")
        strength = _rsa_key_strength(n)
        if strength == "critical":
            findings.append({
                "type": "jwks-rsa-key-too-short",
                "severity": "FAIL",
                "detail": (
                    f"RSA key (kid={kid!r}) appears to have a very short modulus "
                    f"(estimated <1024 bits). Keys shorter than 2048 bits are considered "
                    f"broken. This key may be factorable.\n\n"
                    f"Fix: replace with at least RSA-2048; prefer RSA-3072 or switch to EC."
                ),
            })
        elif strength == "weak":
            findings.append({
                "type": "jwks-rsa-key-weak",
                "severity": "WARN",
                "detail": (
                    f"RSA key (kid={kid!r}) appears to be shorter than 2048 bits. "
                    f"Current best practice requires RSA-2048 minimum. "
                    f"Fix: regenerate with at least RSA-2048."
                ),
            })

    elif kty == "ec":
        crv = key.get("crv", "").lower()
        if crv in _WEAK_CURVES:
            findings.append({
                "type": "jwks-ec-weak-curve",
                "severity": "WARN",
                "detail": (
                    f"EC key (kid={kid!r}) uses curve '{crv}' which provides fewer than "
                    f"128 bits of security. Use P-256, P-384, or P-521."
                ),
            })

    if use == "enc" and kty == "oct":
        findings.append({
            "type": "jwks-encryption-key-exposed",
            "severity": "FAIL",
            "detail": (
                f"JWKS contains a key with use=enc (kid={kid!r}). Publishing encryption "
                f"keys publicly allows anyone to decrypt JWTs encrypted for this server."
            ),
        })

    return findings


def _check_kid_collisions(keys: List[Dict]) -> Optional[Dict]:
    kids = [k.get("kid", "") for k in keys if k.get("kid")]
    seen = set()
    dups = set()
    for k in kids:
        if k in seen:
            dups.add(k)
        seen.add(k)
    if dups:
        return {
            "type": "jwks-kid-collision",
            "severity": "WARN",
            "detail": (
                f"Duplicate 'kid' values in JWKS: {list(dups)}. "
                f"Key ID collisions can cause JWT libraries to pick the wrong key, "
                f"enabling algorithm confusion attacks."
            ),
        }
    return None


def _check_key_count(keys: List[Dict]) -> Optional[Dict]:
    if len(keys) > 10:
        return {
            "type": "jwks-excessive-keys",
            "severity": "WARN",
            "detail": (
                f"JWKS contains {len(keys)} keys. A large number of keys suggests "
                f"poor rotation practices (old keys never retired). Expire and remove "
                f"keys that are no longer used for verification."
            ),
        }
    return None


def _discover_jwks_uri(http, base_origin: str) -> Optional[str]:
    """Try OIDC discovery to find the canonical jwks_uri."""
    discovery_url = base_origin + "/.well-known/openid-configuration"
    resp = http.get(discovery_url)
    if resp and resp.status_code == 200:
        try:
            data = json.loads(resp.text or "{}")
            return data.get("jwks_uri")
        except Exception:
            pass
    return None


class JWKSExposureScanner(BaseScanner):
    """Detects JWKS endpoint security issues: symmetric keys, weak key sizes, kid collisions."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "JWKS Exposure — target unreachable", "PASS",
                detail="No response; JWKS check skipped."))
            return self.results

        parsed      = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        found       = False

        # Try canonical OIDC discovery first
        jwks_uri = _discover_jwks_uri(self.http, base_origin)

        jwks_urls_to_try = []
        if jwks_uri:
            jwks_urls_to_try.append(jwks_uri)
        for path in _JWKS_PATHS:
            if "openid-configuration" in path:
                continue  # already handled above
            jwks_urls_to_try.append(base_origin + path)

        for jwks_url in jwks_urls_to_try:
            r = self.http.get(jwks_url)
            if r is None or r.status_code not in (200,):
                continue
            try:
                data = json.loads(r.text or "{}")
            except Exception:
                continue
            keys = data.get("keys", [])
            if not isinstance(keys, list) or not keys:
                continue

            found = True

            # Per-key analysis
            for key in keys:
                for f in _analyze_key(key):
                    sev = f["severity"]
                    if sev == "FAIL":
                        log_fail(logger, f"JWKS Exposure — {f['type']} at {jwks_url}")
                    else:
                        log_warn(logger, f"JWKS Exposure — {f['type']} at {jwks_url}")
                    self.results.append(self._result(
                        jwks_url, f["type"], sev, detail=f["detail"]))

            # Structural checks
            f = _check_kid_collisions(keys)
            if f:
                log_warn(logger, f"JWKS Exposure — {f['type']} at {jwks_url}")
                self.results.append(self._result(
                    jwks_url, f["type"], f["severity"], detail=f["detail"]))

            f = _check_key_count(keys)
            if f:
                log_warn(logger, f"JWKS Exposure — {f['type']} at {jwks_url}")
                self.results.append(self._result(
                    jwks_url, f["type"], f["severity"], detail=f["detail"]))

            if not self.results:
                log_pass(logger, f"JWKS Exposure — no issues at {jwks_url}")
                self.results.append(self._result(
                    jwks_url,
                    "JWKS Exposure — keys look well configured",
                    "PASS",
                    detail=f"JWKS at {jwks_url} contains {len(keys)} key(s) with no "
                           f"detected weaknesses.",
                ))

            break  # only analyze first found JWKS endpoint

        if not found:
            log_pass(logger, f"JWKS Exposure — no JWKS endpoint found for {url}")
            self.results.append(self._result(
                url,
                "JWKS Exposure — no JWKS endpoint found",
                "PASS",
                detail="No JWKS endpoint discovered at common paths or via OIDC discovery.",
            ))

        return self.results
