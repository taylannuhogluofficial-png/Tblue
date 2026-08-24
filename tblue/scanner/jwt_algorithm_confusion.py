"""JWT algorithm confusion — none algorithm, RS256→HS256 confusion, weak secret indicators."""
import re
import base64
import json as _json
from .base import BaseScanner

_JWT_RE = re.compile(
    r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*',
)
_AUTH_HEADER_RE = re.compile(r'authorization:\s*bearer\s+(\S+)', re.I)
_JWT_COOKIE_RE = re.compile(r'(?:jwt|token|access_token|auth_token)=[^;,\s]+', re.I)


def _decode_jwt_header(token: str) -> dict | None:
    try:
        header_b64 = token.split(".")[0]
        padding = 4 - len(header_b64) % 4
        header_b64 += "=" * (padding % 4)
        return _json.loads(base64.urlsafe_b64decode(header_b64))
    except Exception:
        return None


def _check_jwt_algorithm(header: dict, token_url: str) -> list:
    findings = []
    alg = header.get("alg", "")

    if alg.lower() == "none":
        findings.append({
            "type": "jwt_algorithm_none",
            "status": "FAIL",
            "url": token_url,
            "detail": "JWT uses alg=none — signature verification is disabled, "
                      "any payload is accepted without verification",
        })
    elif alg.upper() in ("HS256", "HS384", "HS512"):
        findings.append({
            "type": "jwt_algorithm_hmac_symmetric",
            "status": "WARN",
            "url": token_url,
            "detail": f"JWT uses symmetric HMAC ({alg}) — if the server also accepts RS256 tokens "
                      "and the RSA public key is known, algorithm confusion attack may work",
        })
    elif alg == "":
        findings.append({
            "type": "jwt_algorithm_missing",
            "status": "FAIL",
            "url": token_url,
            "detail": "JWT header missing 'alg' field — library may default to none or HS256",
        })

    kid = header.get("kid", "")
    if kid and (re.search(r'[/\\]', kid) or ".." in kid):
        findings.append({
            "type": "jwt_kid_path_traversal",
            "status": "FAIL",
            "url": token_url,
            "detail": f"JWT 'kid' header contains path traversal: {kid[:60]} — "
                      "server may read arbitrary file as signing key",
        })

    return findings


def _extract_jwts_from_response(body: str, headers: dict, url: str) -> list:
    findings = []
    all_tokens = set()
    for m in _JWT_RE.finditer(body):
        all_tokens.add(m.group(0))
    for m in _JWT_RE.finditer(headers.get("set-cookie", "")):
        all_tokens.add(m.group(0))

    for token in all_tokens:
        header = _decode_jwt_header(token)
        if header:
            for f in _check_jwt_algorithm(header, url):
                findings.append(f)

    return findings


class JWTAlgorithmConfusionScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "jwt_algo_no_response", "PASS", detail="No response")]

        headers = dict(resp.headers) if resp.headers else {}
        for f in _extract_jwts_from_response(resp.text, headers, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "jwt_algo_clean", "PASS",
                                        detail="No JWT algorithm confusion indicators detected"))
        return results
