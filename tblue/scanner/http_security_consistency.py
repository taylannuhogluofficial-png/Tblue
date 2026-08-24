"""
HTTP Security Header Consistency Scanner.

Security headers applied to the main page may not be consistently applied to:
- API endpoints (e.g., CSP absent on /api/*)
- Static asset paths (e.g., /static/*, /assets/*)
- Error pages (404, 500)
- Redirect responses (301, 302)
- Authentication endpoints (/login, /logout)

Inconsistent headers mean that:
1. An XSS on an API path executes without CSP restriction.
2. Clickjacking on error pages can capture user input.
3. HSTS absent on some paths allows downgrade attacks on those paths.
4. A page without X-Content-Type-Options enables content sniffing on that path.

Security issues checked:

1. CSP on main page but absent on /api/* or /login
2. X-Frame-Options on main page but absent on other paths
3. X-Content-Type-Options on main page but absent on static assets
4. HSTS on main page but absent on API endpoints
5. Referrer-Policy absent on pages with sensitive forms

CWE-693: Protection Mechanism Failure
CWE-116: Improper Encoding or Escaping of Output
"""

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_CHECK_PATHS = [
    "/login", "/signin", "/auth", "/api/v1/", "/api/",
    "/static/style.css", "/assets/app.js",
    "/404", "/error", "/logout", "/signup", "/register",
]

_SECURITY_HEADERS = [
    ("content-security-policy", "CSP"),
    ("x-frame-options", "X-Frame-Options"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("strict-transport-security", "HSTS"),
    ("referrer-policy", "Referrer-Policy"),
]


def _get_headers(resp) -> dict:
    if hasattr(resp.headers, "items"):
        return {k.lower(): v for k, v in resp.headers.items()}
    if isinstance(resp.headers, dict):
        return {k.lower(): v for k, v in resp.headers.items()}
    return {}


class HTTPSecurityConsistencyScanner(BaseScanner):
    """Detect inconsistent security header application across page paths."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0

        try:
            main_resp = self.http.get(url)
        except Exception:
            return self.results

        if main_resp is None:
            self.results.append(self._result(
                url, "Security header consistency — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        main_headers = _get_headers(main_resp)
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        # Build baseline of which security headers are present on main page
        baseline: dict = {}
        for hdr, label in _SECURITY_HEADERS:
            baseline[hdr] = hdr in main_headers and bool(main_headers[hdr])

        # Check other paths
        for path in _CHECK_PATHS:
            if findings >= 8:
                break
            probe_url = base + path
            try:
                probe = self.http.get(probe_url)
            except Exception:
                continue
            if probe is None or probe.status_code not in (200, 401, 403, 404, 302, 301):
                continue

            probe_headers = _get_headers(probe)

            for hdr, label in _SECURITY_HEADERS:
                if not baseline.get(hdr):
                    # Header not on main page either — not an inconsistency
                    continue
                probe_has = hdr in probe_headers and bool(probe_headers[hdr])
                if not probe_has:
                    # Skip static assets for CSP (common to omit CSP on assets)
                    if hdr == "content-security-policy" and any(
                        path.startswith(p) for p in ("/static", "/assets", "/public")
                    ):
                        continue
                    log_warn(logger, f"Security header {label} present on main page but absent on {path}")
                    self.results.append(self._result(
                        url,
                        f"Security header consistency — {label} absent on {path} (present on main page)",
                        "WARN",
                        detail=(
                            f"The {label} header is present on the main page but absent on "
                            f"'{path}' (HTTP {probe.status_code}). "
                            f"Inconsistent header application leaves '{path}' unprotected. "
                            f"An XSS or injection on this path executes without {label} protection. "
                            f"Fix: apply {label} headers consistently to all responses, "
                            "including API endpoints, error pages, and redirects."
                        )
                    ))
                    findings += 1
                    if findings >= 8:
                        break

        if not self.results:
            if any(baseline.values()):
                log_pass(logger, f"Security headers appear consistently applied at {url}")
                self.results.append(self._result(
                    url,
                    "Security header consistency — headers appear consistently applied across sampled paths",
                    "PASS",
                    detail="Security headers found on main page are also present on sampled sub-paths."
                ))
            else:
                log_pass(logger, f"No security headers to check consistency for at {url}")
                self.results.append(self._result(
                    url,
                    "Security header consistency — no baseline security headers to check consistency for",
                    "PASS",
                    detail="Main page has no security headers to compare against sub-paths."
                ))

        return self.results
