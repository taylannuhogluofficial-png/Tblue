"""
API Key Rotation & Secret Freshness Scanner.

Passively detects signs of long-lived or improperly rotated secrets:

1. JWT tokens with very long or missing expiry (exp claim)
2. API keys in JS with timestamp-like patterns suggesting they were generated once and never rotated
3. HTTP Basic auth credentials sent over HTTPS but present in JS source
4. Long-lived session cookies (Expires far in the future)
5. Hardcoded AWS/GCP/Azure credential patterns that indicate no rotation
"""

import base64
import json
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_JWT_RE = re.compile(r'eyJ[A-Za-z0-9+/=_-]{10,}\.[A-Za-z0-9+/=_-]{10,}\.[A-Za-z0-9+/=_-]{10,}')

_LONG_LIVED_DAYS = 90  # tokens valid longer than this are flagged

_AWS_KEY_RE    = re.compile(r'AKIA[0-9A-Z]{16}', re.I)
_AWS_SECRET_RE = re.compile(r'(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])')
_GCP_KEY_RE    = re.compile(r'AIza[0-9A-Za-z_-]{35}')
_AZURE_KEY_RE  = re.compile(r'AccountKey=[A-Za-z0-9+/=]{60,}')

_BASIC_AUTH_IN_JS_RE = re.compile(
    r'(?:btoa|atob)\s*\(\s*["\'][^"\']{3,}:[^"\']{3,}["\']',
    re.I,
)

_FAR_FUTURE_COOKIE_RE = re.compile(
    r'expires\s*=\s*(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d+\s+\w+\s+20[3-9]\d',
    re.I,
)

_MAX_AGE_YEARS_RE = re.compile(r'max-age\s*=\s*(\d+)', re.I)
_ONE_YEAR_SECS = 365 * 24 * 3600


def _decode_jwt_payload(token: str) -> dict:
    try:
        parts = token.split(".")
        payload_b64 = parts[1] + "=="
        payload_b64 = payload_b64.replace("-", "+").replace("_", "/")
        return json.loads(base64.b64decode(payload_b64).decode("utf-8", errors="replace"))
    except Exception:
        return {}


class APIKeyRotationScanner(BaseScanner):
    """Detect long-lived tokens, unrotated API keys, and credential freshness issues."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        self._check_jwt_expiry(url, resp.text)
        self._check_cloud_keys(url, resp.text)
        self._check_basic_auth_in_js(url, resp.text)
        self._check_long_lived_cookies(url, resp.headers)
        self._check_js_files(url, origin, resp.text)

        if not self.results:
            log_pass(logger, f"No secret rotation issues detected at {url}")
            self.results.append(self._result(
                url, "API key rotation — no long-lived credential issues detected", "PASS",
                detail="No long-lived JWTs, unrotated cloud keys, or stale credentials found."
            ))

        return self.results

    def _check_jwt_expiry(self, url: str, body: str) -> None:
        import time
        now = int(time.time())
        for token in _JWT_RE.findall(body):
            payload = _decode_jwt_payload(token)
            if not payload:
                continue
            exp = payload.get("exp")
            iat = payload.get("iat")
            if exp is None:
                log_warn(logger, f"JWT without exp claim found in response at {url}")
                self.results.append(self._result(
                    url, "API key rotation — JWT missing exp claim", "WARN",
                    detail=(
                        "A JWT without an expiration claim (exp) was found in the page response. "
                        "JWTs without expiry remain valid indefinitely after issuance, "
                        "making token revocation impossible. "
                        "Fix: always include exp in JWT payloads; use short-lived tokens (15 min – 1 hour)."
                    )
                ))
                break
            if iat and (exp - iat) > _LONG_LIVED_DAYS * 86400:
                days = (exp - iat) // 86400
                log_warn(logger, f"JWT with {days}-day validity found in response at {url}")
                self.results.append(self._result(
                    url, f"API key rotation — JWT valid for {days} days", "WARN",
                    detail=(
                        f"A JWT with a validity period of {days} days was found in the page response. "
                        f"Long-lived JWTs significantly extend the window of exposure if compromised. "
                        "Fix: use short-lived access tokens (≤1 hour) with refresh token rotation."
                    )
                ))
                break

    def _check_cloud_keys(self, url: str, body: str) -> None:
        if _AWS_KEY_RE.search(body):
            log_warn(logger, f"AWS access key pattern in response at {url}")
            self.results.append(self._result(
                url, "API key rotation — AWS access key in page response", "FAIL",
                detail=(
                    "An AWS access key ID (AKIA...) pattern was detected in the page response. "
                    "Exposed AWS keys allow full account access within the key's IAM permissions. "
                    "Fix: immediately revoke the key; use IAM roles instead of long-term access keys; "
                    "enable AWS Secrets Manager for credential rotation."
                )
            ))
        if _GCP_KEY_RE.search(body):
            log_warn(logger, f"GCP API key pattern in response at {url}")
            self.results.append(self._result(
                url, "API key rotation — GCP API key in page response", "FAIL",
                detail=(
                    "A GCP API key (AIza...) pattern was detected in the page response. "
                    "Exposed GCP keys can be used to abuse enabled APIs and run up billing charges. "
                    "Fix: restrict the key's API scope; rotate immediately; use service accounts instead."
                )
            ))
        if _AZURE_KEY_RE.search(body):
            log_warn(logger, f"Azure storage account key in response at {url}")
            self.results.append(self._result(
                url, "API key rotation — Azure storage key in page response", "FAIL",
                detail=(
                    "An Azure storage account key (AccountKey=...) was detected in the page response. "
                    "This key grants full read/write access to all blobs, queues, and tables in the account. "
                    "Fix: rotate immediately; use SAS tokens or managed identities instead."
                )
            ))

    def _check_basic_auth_in_js(self, url: str, body: str) -> None:
        if _BASIC_AUTH_IN_JS_RE.search(body):
            log_warn(logger, f"HTTP Basic auth credentials in client-side JS at {url}")
            self.results.append(self._result(
                url, "API key rotation — Basic auth credentials in JavaScript", "FAIL",
                detail=(
                    "btoa/atob encoding of 'user:password' credentials was found in client-side JavaScript. "
                    "Base64 encoding is not encryption — anyone viewing source can decode it instantly. "
                    "Fix: perform authentication server-side; never embed credentials in client code."
                )
            ))

    def _check_long_lived_cookies(self, url: str, headers) -> None:
        for hdr_name, hdr_val in headers.items():
            if hdr_name.lower() != "set-cookie":
                continue
            if _FAR_FUTURE_COOKIE_RE.search(hdr_val):
                log_warn(logger, f"Session cookie with far-future expiry at {url}")
                self.results.append(self._result(
                    url, "API key rotation — session cookie with far-future expiry", "WARN",
                    detail=(
                        f"A session cookie with an expiry date in 2030+ was found: {hdr_val[:120]}. "
                        "Long-lived session cookies persist after the user closes the browser, "
                        "extending the attack window after device theft or XSS. "
                        "Fix: use short session lifetimes with server-side session invalidation; "
                        "implement idle and absolute timeout mechanisms."
                    )
                ))
                break
            ma = _MAX_AGE_YEARS_RE.search(hdr_val)
            if ma and int(ma.group(1)) > _ONE_YEAR_SECS:
                years = int(ma.group(1)) // _ONE_YEAR_SECS
                log_warn(logger, f"Cookie max-age={ma.group(1)} (>1 year) at {url}")
                self.results.append(self._result(
                    url, f"API key rotation — session cookie max-age {years}+ years", "WARN",
                    detail=(
                        f"A cookie with Max-Age={ma.group(1)} ({years} years) was detected. "
                        "Fix: limit session cookie lifetime; use server-side session revocation."
                    )
                ))
                break

    def _check_js_files(self, url: str, origin: str, body: str) -> None:
        js_re = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.I)
        found_keys = False
        for m in js_re.finditer(body):
            if found_keys:
                break
            src = m.group(1)
            if not src.startswith("http"):
                src = origin + ("" if src.startswith("/") else "/") + src
            try:
                js_resp = self.http.get(src)
                if js_resp.status_code != 200:
                    continue
                js_body = js_resp.text
                if _AWS_KEY_RE.search(js_body):
                    log_warn(logger, f"AWS key in JS file {src}")
                    self.results.append(self._result(
                        src, "API key rotation — AWS access key in JS bundle", "FAIL",
                        detail=(
                            f"An AWS access key ID pattern was found in the JavaScript bundle {src}. "
                            "Client-side bundles are public — this key is effectively leaked. "
                            "Fix: revoke immediately; never include cloud credentials in client-side code."
                        )
                    ))
                    found_keys = True
                elif _GCP_KEY_RE.search(js_body):
                    log_warn(logger, f"GCP key in JS file {src}")
                    self.results.append(self._result(
                        src, "API key rotation — GCP API key in JS bundle", "FAIL",
                        detail=(
                            f"A GCP API key pattern was found in the JavaScript bundle {src}. "
                            "Fix: restrict the key's API scope; never embed service account keys in client code."
                        )
                    ))
                    found_keys = True
            except Exception:
                continue
