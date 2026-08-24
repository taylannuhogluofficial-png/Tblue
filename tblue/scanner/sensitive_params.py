"""
Sensitive URL parameter detector.

Inspects all URLs discovered during crawling for parameter names that suggest
credentials, tokens, or other sensitive data are being passed in query strings.

Credentials in URLs are dangerous because they:
  - Appear in server access logs in plaintext
  - Are stored in browser history
  - Leak in the Referer header when following external links
  - Are visible to CDN/proxy infrastructure between client and server
"""

from typing import List, Dict, Any, Set
from urllib.parse import urlparse, parse_qs

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

# Parameter names that should never appear in URLs
_SENSITIVE_PARAMS: Dict[str, str] = {
    # Auth tokens
    "token":           "authentication token",
    "access_token":    "OAuth access token",
    "id_token":        "OpenID Connect ID token",
    "refresh_token":   "OAuth refresh token",
    "auth_token":      "authentication token",
    "api_token":       "API token",
    "jwt":             "JSON Web Token",
    "bearer":          "Bearer token",
    "auth":            "authentication credential",

    # API keys
    "api_key":         "API key",
    "apikey":          "API key",
    "key":             "API/auth key",
    "app_key":         "application key",
    "client_secret":   "OAuth client secret",
    "secret":          "secret credential",
    "app_secret":      "application secret",

    # Passwords
    "password":        "plaintext password",
    "passwd":          "plaintext password",
    "pass":            "plaintext password",
    "pwd":             "plaintext password",

    # Session identifiers
    "sessionid":       "session identifier",
    "session_id":      "session identifier",
    "sid":             "session identifier",
    "ssid":            "session identifier",
    "phpsessid":       "PHP session ID",
    "jsessionid":      "Java session ID",
    "aspsessionid":    "ASP session ID",

    # Other sensitive
    "credit_card":     "credit card number",
    "card_number":     "credit card number",
    "cvv":             "card verification value",
    "ssn":             "social security number",
    "pin":             "PIN code",
    "otp":             "one-time password",
    "mfa_code":        "MFA code",
    "totp":            "TOTP code",
    "private_key":     "private key",
}

# Minimum value length to flag (avoids flagging ?key= with empty value)
_MIN_VALUE_LEN = 4


class SensitiveParamScanner(BaseScanner):
    """
    Scans a set of URLs for sensitive data in query string parameters.
    Call scan_urls() when you have a crawled page set; scan() checks only one URL.
    """

    def scan(self, url: str) -> List[Dict[str, Any]]:
        return self.scan_urls([url])

    def scan_urls(self, urls) -> List[Dict[str, Any]]:
        self.results = []
        flagged: Set[str] = set()

        for url in urls:
            findings = _check_url(url)
            for param, description, value in findings:
                key = f"{param}:{url[:80]}"
                if key in flagged:
                    continue
                flagged.add(key)
                masked = value[:4] + "…" if len(value) > 4 else "…"
                log_warn(logger, f"Sensitive param '{param}' in URL: {url[:80]}")
                self.results.append(self._result(
                    url,
                    f"Sensitive URL parameter — {param}",
                    "WARN",
                    detail=(
                        f"The URL contains a {description} in the query string "
                        f"(parameter: {param}={masked}). "
                        "Credentials and tokens in URLs are logged by servers, CDNs, "
                        "proxies, and browsers — and leaked in Referer headers. "
                        "Fix: pass sensitive values in POST body or request headers, "
                        "never in the URL. Use Authorization: Bearer <token> for API tokens."
                    )
                ))

        if not self.results:
            log_pass(logger, "No sensitive parameters found in URLs")
            self.results.append(self._result(
                "crawled pages",
                "Sensitive URL parameters — none detected",
                "PASS",
                detail="No sensitive parameter names (tokens, passwords, API keys) "
                       "found in any crawled URLs."
            ))

        return self.results


def _check_url(url: str) -> List[tuple]:
    """Return list of (param_name, description, value) for sensitive params in url."""
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=False)
    except Exception:
        return []

    findings = []
    for param, values in params.items():
        lower = param.lower()
        if lower in _SENSITIVE_PARAMS:
            val = values[0] if values else ""
            if len(val) >= _MIN_VALUE_LEN:
                findings.append((param, _SENSITIVE_PARAMS[lower], val))
    return findings
