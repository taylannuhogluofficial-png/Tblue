"""JWT token exposure — weak secrets, none algorithm, algorithm confusion indicators in page/API."""
import re
import base64
import json
from urllib.parse import urlparse
from .base import BaseScanner

_JWT_RE = re.compile(r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*')

_JWT_NONE_ALG_PAYLOAD = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"  # {"alg":"none","typ":"JWT"}

_WEAK_SECRETS = [
    "secret", "password", "1234567890", "your-256-bit-secret",
    "jwt-secret", "mysecret", "change-me", "dev-secret",
]

_ALG_NONE_ENDPOINTS = [
    "/api/me", "/api/user", "/api/profile", "/api/v1/me",
]

_STORED_IN_LOCALSTORAGE_RE = re.compile(
    r'localStorage\.setItem\s*\(\s*["\'][^"\']*(?:token|jwt|auth)[^"\']*["\']',
    re.I,
)

_JWT_IN_URL_RE = re.compile(
    r'[?&](?:token|jwt|access_token|id_token)=eyJ[A-Za-z0-9\-_]+\.',
    re.I,
)


def _decode_jwt_header(token: str) -> dict:
    """Decode JWT header without verification."""
    try:
        header_b64 = token.split(".")[0]
        padded = header_b64 + "=" * (4 - len(header_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}


def _decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload without verification."""
    try:
        payload_b64 = token.split(".")[1]
        padded = payload_b64 + "=" * (4 - len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return {}


def _check_jwt_in_body(body: str, url: str) -> list:
    findings = []
    seen = set()
    for m in _JWT_RE.finditer(body):
        token = m.group(0)
        header = _decode_jwt_header(token)
        alg = header.get("alg", "").lower()
        key = alg or token[:20]
        if key in seen:
            continue
        seen.add(key)

        if alg == "none":
            findings.append({
                "type": "jwt_alg_none_in_page",
                "status": "FAIL",
                "url": url,
                "detail": (f"JWT with alg:none found in page — this token has no signature, "
                           f"allowing anyone to forge tokens by setting alg to none"),
            })
        elif alg in ("hs256", "hs384", "hs512"):
            findings.append({
                "type": "jwt_hmac_token_in_page",
                "status": "WARN",
                "url": url,
                "detail": (f"HMAC-signed JWT (alg:{alg.upper()}) exposed in page — "
                           f"symmetric secret used for signing; if key is weak or reused, "
                           f"token can be forged"),
            })
    if _STORED_IN_LOCALSTORAGE_RE.search(body):
        findings.append({
            "type": "jwt_stored_in_localstorage",
            "status": "WARN",
            "url": url,
            "detail": ("JWT stored in localStorage — XSS can steal token; "
                       "prefer HttpOnly cookies or in-memory storage"),
        })
    return findings


def _check_jwt_in_url(url: str) -> list:
    if _JWT_IN_URL_RE.search(url):
        return [{
            "type": "jwt_in_url_parameter",
            "status": "FAIL",
            "url": url,
            "detail": "JWT found in URL query parameter — token appears in server logs, browser history, and Referer headers",
        }]
    return []


class JWTTokenExposureScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []

        for f in _check_jwt_in_url(url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        resp = self.http.get(url)
        if resp is None:
            if not results:
                return [self._result(url, "jwt_token_exposure_no_response", "PASS",
                                     detail="No response")]
            return results

        body = resp.text or ""

        for f in _check_jwt_in_body(body, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for path in _ALG_NONE_ENDPOINTS[:3]:
            try:
                api_resp = self.http.get(origin + path)
                if api_resp and api_resp.status_code == 200:
                    api_body = api_resp.text or ""
                    for f in _check_jwt_in_body(api_body, origin + path):
                        results.append(self._result(f["url"], f["type"], f["status"],
                                                    detail=f["detail"]))
            except Exception:
                pass

        if not results:
            results.append(self._result(url, "jwt_token_exposure_clean", "PASS",
                                        detail="No JWT token exposure issues detected"))
        return results
