"""
CORS Max-Age Deep Scanner.

Access-Control-Max-Age controls how long browsers cache CORS preflight
responses. Misconfigured values create security and usability issues:

  1. Very long max-age — browsers may cache a permissive CORS response for
     days, meaning policy changes (revoking access) take time to propagate.
     OWASP recommends max 600s (10 minutes).

  2. Zero or negative max-age — forces a preflight on every credentialed
     request, increasing latency but also meaning policy changes are
     immediately effective.

  3. Missing Access-Control-Max-Age — browsers apply a browser-default
     (typically 5s); not inherently dangerous but indicates CORS was not
     carefully designed.

  4. Overly permissive methods in Access-Control-Allow-Methods combined
     with long max-age — cached approval for DELETE/PUT/PATCH.

  5. Wildcard allow-headers with long max-age — all headers approved for
     the cache duration.

Read-only passive.

CWE-942: Permissive Cross-domain Policy with Untrusted Domains
"""

from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_MAX_RECOMMENDED_AGE = 600   # 10 minutes
_LONG_MAX_AGE = 86400        # 1 day — definitely too long
_DANGEROUS_METHODS = {"DELETE", "PUT", "PATCH"}


def _check_cors_max_age(headers: dict, url: str) -> List[Dict]:
    findings = []
    acao = headers.get("access-control-allow-origin", "")
    if not acao:
        return findings

    raw_age = headers.get("access-control-max-age", "")
    allow_methods = {m.strip().upper() for m in headers.get("access-control-allow-methods", "").split(",")}
    allow_headers = headers.get("access-control-allow-headers", "")

    if raw_age:
        try:
            age = int(raw_age.strip())
        except ValueError:
            age = None

        if age is not None and age > _LONG_MAX_AGE:
            findings.append({
                "type": "cors-max-age-excessive",
                "status": "WARN",
                "detail": (
                    f"Access-Control-Max-Age at {url} is {age}s ({age // 3600}h).\n\n"
                    f"Browsers cache CORS preflight results for this duration. If you revoke "
                    f"CORS access, existing browser caches will still allow requests for up "
                    f"to {age // 3600} hours.\n\n"
                    f"Fix: set Access-Control-Max-Age to 600s (10 minutes) or less."
                ),
            })
        elif age is not None and age > _MAX_RECOMMENDED_AGE:
            findings.append({
                "type": "cors-max-age-above-recommended",
                "status": "WARN",
                "detail": (
                    f"Access-Control-Max-Age at {url} is {age}s, exceeding the "
                    f"recommended 600s maximum.\n\n"
                    f"A longer cache window delays the effect of CORS policy revocations.\n\n"
                    f"Fix: reduce to 600s or less."
                ),
            })

        if age is not None and age > _MAX_RECOMMENDED_AGE:
            dangerous = allow_methods & _DANGEROUS_METHODS
            if dangerous:
                findings.append({
                    "type": "cors-max-age-cached-dangerous-methods",
                    "status": "WARN",
                    "detail": (
                        f"CORS at {url} caches preflight approval for {age}s including "
                        f"dangerous HTTP methods: {', '.join(sorted(dangerous))}.\n\n"
                        f"Cached DELETE/PUT/PATCH approvals persist in the browser for the "
                        f"full cache duration even after access is revoked server-side.\n\n"
                        f"Fix: reduce Access-Control-Max-Age and limit Allow-Methods to "
                        f"only required methods."
                    ),
                })

            if allow_headers.strip() == "*":
                findings.append({
                    "type": "cors-max-age-wildcard-headers-cached",
                    "status": "WARN",
                    "detail": (
                        f"CORS at {url} caches wildcard Access-Control-Allow-Headers for "
                        f"{age}s — all request headers are pre-approved for this duration.\n\n"
                        f"Fix: specify only required headers and reduce max-age."
                    ),
                })

    return findings


class CORSMaxAgeDeepScanner(BaseScanner):
    """Checks CORS preflight cache duration: excessive max-age, dangerous method caching."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "CORS Max-Age Deep — target unreachable", "PASS",
                detail="No response; CORS max-age check skipped."))
            return self.results

        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        findings = _check_cors_max_age(headers, url)
        found = False

        for f in findings:
            found = True
            log_warn(logger, f"CORS Max-Age Deep — {f['type']}")
            self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"CORS Max-Age Deep — no issues for {url}")
            self.results.append(self._result(
                url, "CORS Max-Age Deep — no CORS max-age issues detected", "PASS",
                detail="No CORS present, or Access-Control-Max-Age is within recommended limits."))

        return self.results
