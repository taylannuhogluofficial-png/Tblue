"""Passive token and secret exposure in URLs, headers, and cookies."""
import re
from urllib.parse import urlparse, parse_qs
from .base import BaseScanner

# Sensitive parameter names that should not appear in URLs
_SENSITIVE_PARAM_NAMES = re.compile(
    r"(?:token|access_token|api[_-]?key|secret|password|passwd|pwd|auth|"
    r"authorization|session[_-]?id|sessid|sid|credential|bearer|client[_-]?secret)",
    re.I,
)

# Token-like values: min 16 chars of hex/base64
_TOKEN_VALUE_RE = re.compile(r"^[A-Za-z0-9+/=_\-]{16,}$")

# JWT in URL
_JWT_URL_RE = re.compile(r"ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")


def _check_sensitive_params_in_url(url: str) -> list:
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    for name, values in params.items():
        if _SENSITIVE_PARAM_NAMES.search(name):
            for val in values:
                if _TOKEN_VALUE_RE.match(val):
                    findings.append({
                        "type": "token_in_url_param",
                        "status": "FAIL",
                        "detail": f"Sensitive parameter '{name}' with token-like value in URL — "
                                  "tokens in URLs are logged by browsers, proxies, and servers",
                    })
    if _JWT_URL_RE.search(url):
        findings.append({
            "type": "jwt_in_url",
            "status": "FAIL",
            "detail": "JWT found in URL — will be logged in server logs and referrer headers",
        })
    return findings


def _check_token_in_response_headers(headers: dict, url: str) -> list:
    findings = []
    for name, value in headers.items():
        if _SENSITIVE_PARAM_NAMES.search(name) and _TOKEN_VALUE_RE.match(value):
            findings.append({
                "type": "token_in_response_header",
                "status": "WARN",
                "detail": f"Response header '{name}' contains a token-like value — "
                          "sensitive data should not appear in response headers",
            })
        if _JWT_URL_RE.search(value):
            findings.append({
                "type": "jwt_in_response_header",
                "status": "WARN",
                "detail": f"JWT found in response header '{name}' — review necessity",
            })
    return findings


def _check_token_in_cookies(headers: dict, url: str) -> list:
    findings = []
    raw_cookies = [v for k, v in headers.items() if k.lower() == "set-cookie"]
    for cookie in raw_cookies:
        name_part = cookie.split("=")[0].strip()
        value_part = cookie.split("=")[1].split(";")[0].strip() if "=" in cookie else ""
        if _SENSITIVE_PARAM_NAMES.search(name_part) and not value_part.startswith("eyJ"):
            # JWT-based session tokens are OK in cookies
            if value_part and _TOKEN_VALUE_RE.match(value_part):
                if "secure" not in cookie.lower():
                    findings.append({
                        "type": "token_cookie_missing_secure",
                        "status": "FAIL",
                        "detail": f"Session/token cookie '{name_part}' missing Secure flag",
                    })
    return findings


class TokenExposurePassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []

        # Check current URL for token leakage
        for f in _check_sensitive_params_in_url(url):
            results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        resp = self.http.get(url)
        if resp is None:
            if not results:
                return [self._result(url, "token_exposure_no_response", "PASS",
                                     detail="No response")]
            return results

        headers = dict(resp.headers)

        for f in _check_token_in_response_headers(headers, url):
            results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        for f in _check_token_in_cookies(headers, url):
            results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        # Scan response body for tokens in hrefs/src attributes
        if _SENSITIVE_PARAM_NAMES.search(resp.text) and _TOKEN_VALUE_RE.search(resp.text):
            # More targeted: look for token params in anchor hrefs
            href_re = re.compile(
                r'href=["\'][^"\']*(?:' + _SENSITIVE_PARAM_NAMES.pattern + r')=[A-Za-z0-9_\-]{16,}',
                re.I,
            )
            if href_re.search(resp.text):
                results.append(self._result(url, "token_in_href", "WARN",
                                            detail="Token-like value in anchor href — "
                                                   "clicks send token to destination via Referer"))

        if not results:
            results.append(self._result(url, "token_exposure_clean", "PASS",
                                        detail="No passive token exposure detected"))
        return results
