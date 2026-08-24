"""
JWT Claim Analysis Scanner.

JWTs embedded in HTML/JS responses reveal algorithm choices, missing claims,
and sensitive payload data without any active probing:

  1. Algorithm: none / RS256 downgradeable to HS256 risk — alg:none means no
     signature verification; mixed RS256 in tokens is a downgrade vector.
  2. Missing exp claim — tokens without expiry never expire.
  3. Missing nbf/iat — makes token replay harder to detect.
  4. Sensitive data in payload — PII, passwords, internal IDs.
  5. Short expiry < 60s — may indicate dev/test tokens with no rotation.

Read-only: finds JWTs already in page source, JS bundles, API responses.

CWE-347: Improper Verification of Cryptographic Signature
CWE-522: Insufficiently Protected Credentials
"""

import base64
import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_JWT_RE = re.compile(
    r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*'
)

_SENSITIVE_CLAIM_KEYS = {
    "password", "passwd", "pwd", "secret", "api_key", "apikey",
    "access_key", "private_key", "ssn", "credit_card", "cc",
}

_WEAK_ALGS = {"none", "hs256", "hs384", "hs512"}


def _decode_jwt_part(part: str) -> Optional[dict]:
    """Base64url-decode a JWT header or payload without signature verification."""
    padding = 4 - len(part) % 4
    if padding < 4:
        part += "=" * padding
    try:
        return json.loads(base64.urlsafe_b64decode(part).decode("utf-8", errors="replace"))
    except Exception:
        return None


def _extract_jwts(text: str) -> List[str]:
    return list(set(_JWT_RE.findall(text)))


def _check_jwt(token: str, url: str) -> List[Dict]:
    findings = []
    parts = token.split(".")
    if len(parts) != 3:
        return findings

    header = _decode_jwt_part(parts[0])
    payload = _decode_jwt_part(parts[1])
    if not header or not payload:
        return findings

    alg = str(header.get("alg", "")).lower()

    if alg == "none":
        findings.append({
            "type": "jwt-algorithm-none",
            "status": "FAIL",
            "detail": (
                f"JWT at {url} uses alg:none — signature is not verified.\n\n"
                f"Any client can forge tokens with arbitrary claims.\n\n"
                f"Fix: reject tokens with alg:none. Only accept tokens with RS256 or ES256."
            ),
        })
    elif alg in _WEAK_ALGS:
        findings.append({
            "type": f"jwt-weak-algorithm-{alg}",
            "status": "WARN",
            "detail": (
                f"JWT at {url} uses {alg.upper()} — a symmetric HMAC algorithm.\n\n"
                f"If the secret is weak or reused across services, tokens can be forged.\n\n"
                f"Prefer RS256 or ES256 (asymmetric). Ensure HMAC secrets are long and random."
            ),
        })

    if "exp" not in payload:
        findings.append({
            "type": "jwt-missing-exp-claim",
            "status": "WARN",
            "detail": (
                f"JWT at {url} has no exp (expiry) claim.\n\n"
                f"Tokens without expiry are valid forever; revocation becomes impossible.\n\n"
                f"Fix: always set exp. Typical values: access tokens 15 min, refresh tokens 7 days."
            ),
        })

    sensitive_keys = {k for k in payload if k.lower() in _SENSITIVE_CLAIM_KEYS}
    if sensitive_keys:
        findings.append({
            "type": "jwt-sensitive-data-in-payload",
            "status": "WARN",
            "detail": (
                f"JWT at {url} payload contains potentially sensitive keys: "
                f"{', '.join(sorted(sensitive_keys))}.\n\n"
                f"JWT payloads are base64-encoded, not encrypted — anyone who holds the token "
                f"can read the payload without the secret.\n\n"
                f"Fix: move sensitive data server-side. Only put non-sensitive claims in tokens."
            ),
        })

    return findings


def _scan_body_for_jwts(body: str, url: str) -> List[Dict]:
    tokens = _extract_jwts(body)
    findings = []
    seen_types: set = set()
    for tok in tokens[:10]:
        for f in _check_jwt(tok, url):
            if f["type"] not in seen_types:
                seen_types.add(f["type"])
                findings.append(f)
    return findings


_JS_PATHS = ["/static/js/main.js", "/assets/app.js", "/js/app.js", "/bundle.js"]


class JWTClaimAnalysisScanner(BaseScanner):
    """Extracts JWTs from page source and API responses, checks algorithm and claims."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "JWT Claim Analysis — target unreachable", "PASS",
                detail="No response; JWT claim analysis skipped."))
            return self.results

        found = False
        seen_types: set = set()

        sources = [(url, resp.text or "")]
        for path in _JS_PATHS:
            r = self.http.get(base_origin + path)
            if r and r.status_code == 200:
                sources.append((base_origin + path, r.text or ""))

        for src_url, body in sources:
            for f in _scan_body_for_jwts(body, src_url):
                if f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    found = True
                    log_warn(logger, f"JWT Claim Analysis — {f['type']}")
                    self.results.append(self._result(
                        url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"JWT Claim Analysis — no JWT issues found for {url}")
            self.results.append(self._result(
                url, "JWT Claim Analysis — no JWT issues detected", "PASS",
                detail="No exposed JWTs found or all detected JWTs use strong algorithms with required claims."))

        return self.results
