"""
Rate limiting detection scanner.

Sends several rapid identical POST requests to the login endpoint (or base URL
if no login form is found) and checks whether the server enforces any kind of
rate limiting. This is passive observation only — no passwords are guessed.

Signals checked (any one is enough for PASS):
  - HTTP 429 Too Many Requests on any request
  - X-RateLimit-* or RateLimit-* response headers
  - Retry-After response header
  - Account lockout / rate limit message in response body
"""

import re
import time
from typing import List, Dict, Any
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_LOGIN_PATHS = [
    "/login", "/signin", "/sign-in", "/auth", "/account/login",
    "/user/login", "/users/sign_in", "/session", "/sessions/new",
    "/wp-login.php", "/admin/login", "/api/auth/login", "/api/login",
]

_RATE_LIMIT_HEADERS = re.compile(
    r"^(x-ratelimit|ratelimit|x-rate-limit|retry-after|x-retry-after)",
    re.I
)

_LOCKOUT_PATTERNS = re.compile(
    r"(too many (requests|attempts|logins)|rate.?limit|account.?lock|"
    r"temporarily (blocked|disabled)|try again in|please wait)",
    re.I
)

_PROBE_COUNT  = 6   # rapid requests — enough to trigger most limiters
_PROBE_BODY   = {"username": "tblue_probe", "password": "tblue_probe_xyz"}
_PROBE_DELAY  = 0.05  # 50 ms between probes — fast enough to trigger, not DoS


class RateLimitScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        endpoint, method = self._find_endpoint(url)

        if method == "POST":
            log_msg = f"Rate limit probe on login: {endpoint}"
        else:
            log_msg = f"Rate limit probe on base URL: {endpoint}"
        logger.info(log_msg)

        limited = self._probe(endpoint, method)

        if limited:
            log_pass(logger, f"Rate limiting enforced — {endpoint}")
            self.results.append(self._result(
                endpoint, "Rate limiting — enforced", "PASS",
                detail=f"Rate limiting is active on {endpoint}. "
                       f"The server returned a 429 status or rate-limit headers within "
                       f"{_PROBE_COUNT} rapid requests."
            ))
        else:
            log_warn(logger, f"No rate limiting detected — {endpoint}")
            self.results.append(self._result(
                endpoint, "Rate limiting — not detected", "WARN",
                detail=(
                    f"No rate limiting was observed on {endpoint} after {_PROBE_COUNT} rapid "
                    f"identical requests. Without rate limiting, login endpoints are vulnerable "
                    f"to credential stuffing and password spraying. "
                    f"Fix: implement rate limiting at the application or CDN/proxy layer. "
                    f"Django: use django-axes or django-ratelimit. "
                    f"Express: express-rate-limit. "
                    f"Nginx: limit_req_zone. "
                    f"Cloudflare: Rate Limiting rules."
                )
            ))

        return self.results

    def _find_endpoint(self, url: str) -> tuple:
        """Find the login endpoint or fall back to base URL."""
        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        for path in _LOGIN_PATHS:
            candidate = urljoin(base, path)
            resp = self.http.get(candidate, allow_redirects=True)
            if resp and resp.status_code == 200:
                body = (resp.text or "").lower()
                if any(kw in body for kw in ("password", "passwd", "log in", "sign in")):
                    return candidate, "POST"

        return url, "GET"

    def _probe(self, endpoint: str, method: str) -> bool:
        """Send rapid repeated requests. Return True if rate limiting is detected."""
        for i in range(_PROBE_COUNT):
            try:
                if method == "POST":
                    resp = self.http.post(endpoint, data=_PROBE_BODY)
                else:
                    resp = self.http.get(endpoint)

                if not resp:
                    continue

                if resp.status_code == 429:
                    return True

                for header in resp.headers:
                    if _RATE_LIMIT_HEADERS.match(header):
                        return True

                body = resp.text or ""
                if _LOCKOUT_PATTERNS.search(body):
                    return True

            except Exception:
                pass

            if i < _PROBE_COUNT - 1:
                time.sleep(_PROBE_DELAY)

        return False
