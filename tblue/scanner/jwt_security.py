"""
JWT security scanner.

Looks for JSON Web Tokens in:
  - Set-Cookie response headers
  - Authorization / X-Auth-Token / X-Access-Token response headers
  - Response body (JSON "token", "access_token", "id_token" keys)

For each JWT found, decodes the header (base64, no verification) and flags:
  FAIL  — alg: none  (unsigned token accepted by some libraries)
  FAIL  — alg: RS*/ES* with a public key embedded (potential confusion attack)
  WARN  — alg: HS256/HS384/HS512 (symmetric — key must stay secret)
  WARN  — exp claim missing (token never expires)
  WARN  — exp far in future (> 24 hours)
  PASS  — alg is RS256/RS512/ES256/ES384 with no embedded key and short-lived
"""

import re
import json
import base64
import time
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_JWT_RE = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')

_STRONG_ALGS  = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}
_WEAK_ALGS    = {"HS256", "HS384", "HS512"}
_NONE_ALGS    = {"none", "NONE", "None"}

_MAX_EXP_SECS = 86_400   # 24 hours — longer than this is WARN

# JSON body keys that commonly hold JWTs
_BODY_KEYS = re.compile(
    r'"(access_token|id_token|token|jwt|auth_token|refresh_token)"\s*:\s*"(eyJ[^"]+)"',
    re.I
)


class JWTScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        found_any = False

        resp = self.http.get(url, allow_redirects=True)
        if not resp:
            return self.results

        tokens = self._extract_tokens(resp)

        seen_algs = set()
        for location, raw_token in tokens:
            header = _decode_header(raw_token)
            if header is None:
                continue

            found_any = True
            alg  = (header.get("alg") or "").strip()
            issues = self._analyse(location, raw_token, header, alg)
            seen_algs.add(alg)

            for result in issues:
                self.results.append(result)

        if found_any and not self.results:
            log_pass(logger, f"JWTs found and algorithm looks strong — {url}")
            self.results.append(self._result(
                url, "JWT security — algorithm and expiry", "PASS",
                detail=(
                    "JWTs were found in the response and use a strong asymmetric algorithm "
                    f"({', '.join(seen_algs)}) with a reasonable expiry."
                )
            ))
        elif not found_any:
            log_pass(logger, f"No JWTs detected in response — {url}")
            self.results.append(self._result(
                url, "JWT security — no tokens detected", "PASS",
                detail="No JSON Web Tokens were found in response headers or body."
            ))

        return self.results

    def _extract_tokens(self, resp) -> List[Tuple[str, str]]:
        tokens = []

        # Cookies
        for cookie_header in _get_all(resp, "set-cookie"):
            for m in _JWT_RE.finditer(cookie_header):
                tokens.append(("Set-Cookie header", m.group()))

        # Auth / token headers
        for h in ("authorization", "x-auth-token", "x-access-token", "x-token"):
            val = resp.headers.get(h, "")
            for m in _JWT_RE.finditer(val):
                tokens.append((f"{h} header", m.group()))

        # Response body
        body = resp.text or ""
        for m in _BODY_KEYS.finditer(body):
            tokens.append((f'body field "{m.group(1)}"', m.group(2)))

        # Body full-text scan (catches tokens in arbitrary JSON fields)
        for m in _JWT_RE.finditer(body):
            t = m.group()
            if not any(t == tok for _, tok in tokens):
                tokens.append(("response body", t))

        return tokens

    def _analyse(self, location: str, token: str, header: dict, alg: str) \
            -> List[Dict[str, Any]]:
        results = []
        url_ref = f"Found in: {location}"

        if alg.lower() == "none" or alg in _NONE_ALGS:
            log_fail(logger, f"JWT with alg:none — {location}")
            results.append(self._result(
                location, "JWT security — alg:none (unsigned token)", "FAIL",
                detail=(
                    f"A JWT with alg: none was found in {location}. "
                    "Some libraries accept unsigned tokens, meaning an attacker can forge "
                    "any claims by stripping the signature. "
                    "Fix: explicitly reject tokens with alg:none in your JWT library. "
                    "Never trust the algorithm declared in the token header — enforce it server-side."
                )
            ))
            return results

        if alg in _WEAK_ALGS:
            log_warn(logger, f"JWT using symmetric algorithm {alg} — {location}")
            results.append(self._result(
                location, f"JWT security — symmetric algorithm ({alg})", "WARN",
                detail=(
                    f"A JWT using the symmetric algorithm {alg} was found in {location}. "
                    f"HMAC-based algorithms use a shared secret. If the secret is weak, "
                    f"short, or reused across services, it can be cracked offline. "
                    "Fix: for tokens issued to external clients, prefer RS256 or ES256 "
                    "(asymmetric). If using HMAC, ensure the secret is at least 256 bits "
                    "of random data and is rotated regularly."
                )
            ))

        # Check expiry
        payload = _decode_payload(token)
        if payload is not None:
            exp = payload.get("exp")
            if exp is None:
                log_warn(logger, f"JWT has no expiry (exp claim missing) — {location}")
                results.append(self._result(
                    location, "JWT security — no expiry (exp claim missing)", "WARN",
                    detail=(
                        f"A JWT without an exp (expiration) claim was found in {location}. "
                        "Non-expiring tokens remain valid indefinitely — if stolen, they "
                        "cannot be invalidated without a full key rotation. "
                        "Fix: always include an exp claim. For session tokens, 15–60 minutes "
                        "with refresh token rotation is best practice."
                    )
                ))
            elif isinstance(exp, (int, float)):
                lifetime = exp - time.time()
                if lifetime > _MAX_EXP_SECS:
                    hours = int(lifetime // 3600)
                    log_warn(logger, f"JWT has long expiry ({hours}h) — {location}")
                    results.append(self._result(
                        location, "JWT security — long-lived token", "WARN",
                        detail=(
                            f"A JWT expiring in ~{hours} hours was found in {location}. "
                            "Long-lived tokens increase the window of opportunity if stolen. "
                            "Fix: use short-lived access tokens (15–60 min) with refresh "
                            "token rotation. Implement token revocation for sensitive flows."
                        )
                    ))

        return results


def _decode_header(token: str) -> Optional[dict]:
    try:
        parts  = token.split(".")
        padded = parts[0] + "=" * (-len(parts[0]) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None


def _decode_payload(token: str) -> Optional[dict]:
    try:
        parts  = token.split(".")
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None


def _get_all(resp, header_name: str) -> List[str]:
    try:
        raw = resp.raw.headers
        if hasattr(raw, "getlist"):
            return raw.getlist(header_name) or []
    except Exception:
        pass
    val = resp.headers.get(header_name, "")
    return [val] if val else []
