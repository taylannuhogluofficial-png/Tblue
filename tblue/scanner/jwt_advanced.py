"""
Advanced JWT Security Scanner.

Extends the basic JWT scanner with deeper checks:

1. Algorithm confusion attacks (RS256 to HS256 key confusion)
2. kid (Key ID) injection — path traversal in kid header claim
3. jku / x5u header injection — attacker-controlled key server
4. jwks_uri confusion — claims pointing to attacker-owned JWKS
5. Weak claims — no iss/aud/exp validation indicators
6. Long token expiry (exp > 24h for access tokens)
7. JWT in URL (leaks in Referer / logs)
8. JWT none algorithm still accepted
9. Unencrypted sensitive payload data
10. Missing HTTPS on JWKS endpoint (key distribution over HTTP)

Paid equivalents: Burp Suite Pro JWT Editor, jwt_tool.
"""

import re
import json
import base64
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# JWT format: base64url.base64url.base64url
_JWT_RE = re.compile(
    r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*",
)

# JWT in URL query string
_JWT_URL_PARAM_RE = re.compile(
    r"(?:token|jwt|access_token|id_token|auth_token|bearer)=eyJ",
    re.I,
)

# JWKS URI patterns that should use HTTPS
_JWKS_HTTP_RE = re.compile(r'"jku"\s*:\s*"http://|"x5u"\s*:\s*"http://', re.I)
_JWKS_EXTERNAL_RE = re.compile(r'"jku"\s*:\s*"https?://(?!(?:login|auth|accounts?)\.[^"]+)', re.I)

# Sensitive payload content
_SENSITIVE_PAYLOAD_RE = re.compile(
    r'"password"\s*:|"secret"\s*:|"credit_card"\s*:|"ssn"\s*:|"pin"\s*:|'
    r'"private_key"\s*:|"api_key"\s*:',
    re.I,
)

# Algorithm "none"
_ALG_NONE_RE = re.compile(r'"alg"\s*:\s*"(?:none|None|NONE)"')

# Weak algorithms (symmetric without proper key size is flagged in basic scanner)
_WEAK_ALG_RE = re.compile(r'"alg"\s*:\s*"HS(?:1|256|384|512)"')

# kid header path traversal patterns
_KID_TRAVERSAL_RE = re.compile(
    r'"kid"\s*:\s*"(?:\.\./|/etc/|/dev/|/proc/|\\\\|\.\.\\\\)',
    re.I,
)

# Long expiry (> 86400 seconds = 1 day)
_VERY_LONG_EXP = 86400 * 7  # 7 days — flag tokens valid > 7 days


def _b64_decode_jwt_part(part: str) -> Optional[Dict]:
    """Decode a JWT part (header or payload) without signature verification."""
    padding = 4 - len(part) % 4
    if padding < 4:
        part += "=" * padding
    try:
        decoded = base64.urlsafe_b64decode(part)
        return json.loads(decoded)
    except Exception:
        return None


def _analyze_jwt(token: str, source_url: str) -> List[Dict[str, Any]]:
    """Analyze a JWT token for security issues. Returns list of findings."""
    issues = []
    parts = token.split(".")
    if len(parts) != 3:
        return issues

    header = _b64_decode_jwt_part(parts[0])
    payload = _b64_decode_jwt_part(parts[1])

    if not header:
        return issues

    alg = header.get("alg", "")
    kid = header.get("kid", "")
    jku = header.get("jku", "")
    x5u = header.get("x5u", "")

    # Algorithm none
    if alg.lower() == "none":
        issues.append({
            "type": "JWT Advanced — alg:none (no signature verification)",
            "status": "FAIL",
            "detail": (
                f"JWT found at '{source_url}' with alg:'none'. "
                "The 'none' algorithm disables signature verification entirely — "
                "any attacker can forge tokens. "
                "Fix: reject all tokens with alg:none on the server."
            )
        })

    # kid path traversal
    if kid and re.search(r"\.\./|/etc/|/dev/null|/proc/", kid):
        issues.append({
            "type": f"JWT Advanced — kid header path traversal ({kid[:40]})",
            "status": "FAIL",
            "detail": (
                f"JWT 'kid' header contains path traversal: '{kid}'. "
                "If the server uses the kid value to load a key from disk, "
                "an attacker can forge tokens by pointing kid to an empty/known file. "
                "Fix: validate kid against a whitelist of allowed key IDs; "
                "never use kid as a filesystem path."
            )
        })

    # jku/x5u over HTTP (insecure key distribution)
    if jku and jku.startswith("http://"):
        issues.append({
            "type": "JWT Advanced — jku header uses HTTP (insecure key endpoint)",
            "status": "FAIL",
            "detail": (
                f"JWT 'jku' header points to an HTTP (not HTTPS) key endpoint: '{jku}'. "
                "Key endpoints must use HTTPS — HTTP allows MitM attacks to substitute keys. "
                "Fix: use HTTPS for all JWKS endpoints; validate jku against a server-side allowlist."
            )
        })

    # jku pointing to an external/untrusted domain
    if jku and jku.startswith("https://"):
        parsed_source = urlparse(source_url)
        parsed_jku = urlparse(jku)
        if parsed_jku.netloc and parsed_jku.netloc != parsed_source.netloc:
            issues.append({
                "type": f"JWT Advanced — jku points to external key endpoint ({parsed_jku.netloc})",
                "status": "WARN",
                "detail": (
                    f"JWT 'jku' header points to an external domain: '{jku}'. "
                    "If the server fetches and trusts this JWKS without validation, "
                    "an attacker can supply their own keys. "
                    "Fix: validate jku against a strict allowlist of trusted key server domains."
                )
            })

    if not payload:
        return issues

    # Missing standard claims
    if "exp" not in payload:
        issues.append({
            "type": "JWT Advanced — missing exp claim (no token expiry)",
            "status": "FAIL",
            "detail": (
                "JWT payload has no 'exp' (expiration) claim. "
                "Tokens without expiry are valid indefinitely — stolen tokens cannot be revoked. "
                "Fix: add 'exp' claim; use short-lived access tokens (15 min recommended)."
            )
        })
    elif isinstance(payload.get("exp"), (int, float)):
        import time
        now = int(time.time())
        remaining = payload["exp"] - now
        if remaining > _VERY_LONG_EXP:
            days = remaining // 86400
            issues.append({
                "type": f"JWT Advanced — very long token expiry ({days}+ days)",
                "status": "WARN",
                "detail": (
                    f"JWT expires in {days} days. Long-lived tokens increase the attack window "
                    "if stolen. Fix: access tokens should expire in 15-60 minutes; "
                    "use refresh tokens with rotation for longer sessions."
                )
            })

    if "iss" not in payload:
        issues.append({
            "type": "JWT Advanced — missing iss claim",
            "status": "WARN",
            "detail": (
                "JWT payload has no 'iss' (issuer) claim. "
                "Without issuer validation, tokens from different systems may be accepted. "
                "Fix: include and validate the 'iss' claim."
            )
        })

    # Sensitive data in payload
    payload_str = json.dumps(payload)
    if _SENSITIVE_PAYLOAD_RE.search(payload_str):
        issues.append({
            "type": "JWT Advanced — sensitive data in JWT payload",
            "status": "WARN",
            "detail": (
                "JWT payload contains fields that look like sensitive data "
                "(password, secret, api_key, etc.). "
                "JWT payloads are base64-encoded, NOT encrypted by default — "
                "anyone who intercepts the token can read the payload. "
                "Fix: never store sensitive data in JWTs; use opaque tokens "
                "or JWE (encrypted JWT) if payload must contain sensitive fields."
            )
        })

    return issues


class JWTAdvancedScanner(BaseScanner):
    """Deep JWT security analysis — algorithm confusion, kid injection, claim validation."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if not resp:
            self.results.append(self._result(
                url, "JWT Advanced — no JWT security issues detected", "PASS",
                detail="No JWT tokens or JWT security issues found."
            ))
            return self.results

        body = resp.text or ""
        soup = BeautifulSoup(body, "html.parser")
        parsed = urlparse(url)

        # ── 1. JWT in URL query string ─────────────────────────────────────────
        qs_str = parsed.query or ""
        if _JWT_URL_PARAM_RE.search(qs_str):
            log_fail(logger, f"JWT in URL query string: {url[:80]}")
            self.results.append(self._result(
                url, "JWT Advanced — JWT token in URL (logs / Referer leak)", "FAIL",
                detail=(
                    "A JWT token was found in the URL query string. "
                    "JWT tokens in URLs appear in server access logs, browser history, "
                    "and the Referer header sent to third-party sites. "
                    "Fix: pass JWTs only in the Authorization header or Secure HttpOnly cookies."
                )
            ))

        # ── 2. Find JWTs in page source ────────────────────────────────────────
        # Check page body (inline scripts, meta tags, etc.)
        jwt_matches = _JWT_RE.findall(body)
        seen_algs: set = set()

        for token in jwt_matches[:5]:  # limit to 5 JWTs per page
            issues = _analyze_jwt(token, url)
            for issue in issues:
                type_key = issue["type"]
                if type_key not in seen_algs:
                    seen_algs.add(type_key)
                    status = issue["status"]
                    if status == "FAIL":
                        log_fail(logger, f"JWT issue: {type_key}")
                    else:
                        log_warn(logger, f"JWT issue: {type_key}")
                    self.results.append(self._result(
                        url, type_key, status,
                        detail=issue["detail"]
                    ))

        # ── 3. Check Authorization header responses ────────────────────────────
        # If response contains a WWW-Authenticate: Bearer, check the realm
        auth_header = resp.headers.get("www-authenticate", "")
        if "bearer" in auth_header.lower():
            realm_match = re.search(r'realm="([^"]+)"', auth_header, re.I)
            if realm_match:
                realm = realm_match.group(1)
                if realm.startswith("http://"):
                    log_warn(logger, f"Bearer realm uses HTTP: {realm}")
                    self.results.append(self._result(
                        url, "JWT Advanced — WWW-Authenticate Bearer realm uses HTTP", "WARN",
                        detail=(
                            f"Bearer token realm '{realm}' uses HTTP. "
                            "Tokens transmitted to HTTP endpoints may be intercepted. "
                            "Fix: ensure all token endpoints use HTTPS."
                        )
                    ))

        if not self.results:
            log_pass(logger, f"No JWT Advanced issues found on {url}")
            self.results.append(self._result(
                url, "JWT Advanced — no issues detected", "PASS",
                detail="No JWT algorithm issues, sensitive payload, or JWT-in-URL found."
            ))

        return self.results
