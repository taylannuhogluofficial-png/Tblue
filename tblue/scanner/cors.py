"""
CORS misconfiguration scanner.

Probes the target URL with crafted Origin headers to detect:
- Reflected-origin with credentials (critical — trivial account takeover)
- Null origin accepted (high — sandbox iframe bypass)
- Wildcard with credentials (high — spec violation)
- Wildcard without credentials (warn — any site reads your responses)
- Subdomain-wildcard reflection (warn — subdomain takeover → CORS bypass)
"""

from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_EVIL_ORIGIN = "https://evil-tblue-probe.com"
_NULL_ORIGIN = "null"


def _acao(resp) -> str:
    return (resp.headers.get("access-control-allow-origin", "") or "").strip()


def _acac(resp) -> bool:
    return (resp.headers.get("access-control-allow-credentials", "")).strip().lower() == "true"


class CORSScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        self._probe_reflected(url)
        self._probe_null(url)
        self._probe_wildcard(url)

        if not self.results:
            log_pass(logger, f"CORS policy looks restrictive — {url}")
            self.results.append(self._result(
                url, "CORS — policy", "PASS",
                detail="No CORS misconfiguration detected. The server does not reflect arbitrary origins."
            ))

        return self.results

    def _get(self, url: str, origin: str):
        try:
            return self.http.get(url, allow_redirects=False,
                                 headers={"Origin": origin})
        except Exception:
            return None

    def _probe_reflected(self, url: str) -> None:
        resp = self._get(url, _EVIL_ORIGIN)
        if not resp:
            return

        acao = _acao(resp)
        creds = _acac(resp)

        if acao != _EVIL_ORIGIN:
            # Check subdomain reflection
            parsed = urlparse(url)
            sub_evil = f"https://evil.{parsed.hostname}"
            resp2 = self._get(url, sub_evil)
            if resp2 and _acao(resp2) == sub_evil:
                log_warn(logger, f"CORS: subdomain-wildcard reflection — {url}")
                self.results.append(self._result(
                    url, "CORS — subdomain-wildcard ACAO reflection", "WARN",
                    detail=(
                        f"The server reflects any subdomain of {parsed.hostname} in ACAO. "
                        "A subdomain takeover (dangling DNS, misconfigured S3) would allow "
                        "an attacker to bypass this check and read cross-origin responses. "
                        "Fix: maintain an explicit allowlist of full origins rather than "
                        "matching by substring or suffix."
                    )
                ))
            return

        if creds:
            log_fail(logger, f"CORS: reflected origin + credentials — {url}")
            self.results.append(self._result(
                url, "CORS — reflected origin with credentials", "FAIL",
                detail=(
                    "The server reflects any Origin in Access-Control-Allow-Origin "
                    "AND sets Access-Control-Allow-Credentials: true. "
                    "This is the most severe CORS misconfiguration: any website can make "
                    "authenticated (cookie-carrying) cross-origin requests and read the full response. "
                    "Fix: use a strict static allowlist of trusted origins; never combine "
                    "a reflected/wildcard ACAO with Access-Control-Allow-Credentials: true."
                )
            ))
        else:
            log_warn(logger, f"CORS: reflected origin (no credentials) — {url}")
            self.results.append(self._result(
                url, "CORS — origin reflected without credentials", "WARN",
                detail=(
                    "The server reflects any Origin in Access-Control-Allow-Origin. "
                    "Cookies are not exposed (no ACAC: true), but any site can read "
                    "unauthenticated API responses or infer data from response timing/size. "
                    "Fix: replace the reflection logic with a static allowlist."
                )
            ))

    def _probe_null(self, url: str) -> None:
        resp = self._get(url, _NULL_ORIGIN)
        if not resp:
            return

        acao = _acao(resp)
        if acao != "null":
            return

        creds = _acac(resp)
        if creds:
            log_fail(logger, f"CORS: null origin + credentials — {url}")
            self.results.append(self._result(
                url, "CORS — null origin with credentials", "FAIL",
                detail=(
                    "The server trusts Origin: null with Access-Control-Allow-Credentials: true. "
                    "null is sent from sandboxed iframes and local HTML files — "
                    "an attacker on any page can embed a sandboxed iframe pointing at your API "
                    "and read the authenticated response. "
                    "Fix: remove null from your CORS allowlist."
                )
            ))
        else:
            log_warn(logger, f"CORS: null origin accepted — {url}")
            self.results.append(self._result(
                url, "CORS — null origin accepted", "WARN",
                detail=(
                    "The server returns Access-Control-Allow-Origin: null. "
                    "This can be exploited via sandboxed iframes or local HTML files. "
                    "Fix: remove null from your CORS allowlist."
                )
            ))

    def _probe_wildcard(self, url: str) -> None:
        resp = self._get(url, "https://tblue-check.com")
        if not resp:
            return

        acao = _acao(resp)
        if acao != "*":
            return

        creds = _acac(resp)
        if creds:
            log_warn(logger, f"CORS: wildcard ACAO + credentials header (spec-invalid) — {url}")
            self.results.append(self._result(
                url, "CORS — wildcard ACAO with credentials header", "WARN",
                detail=(
                    "The server sends both Access-Control-Allow-Origin: * and "
                    "Access-Control-Allow-Credentials: true. Browsers reject this combination "
                    "(it is spec-invalid), but the CORS code on this server may also reflect "
                    "arbitrary origins with credentials for authenticated requests. "
                    "Fix: use an explicit origin allowlist instead of *."
                )
            ))
        else:
            log_warn(logger, f"CORS: wildcard ACAO — {url}")
            self.results.append(self._result(
                url, "CORS — wildcard Access-Control-Allow-Origin", "WARN",
                detail=(
                    "Access-Control-Allow-Origin: * allows any website to read responses "
                    "from this endpoint. If the endpoint returns any non-public data "
                    "(user IDs, tokens, counts, PII), this is exploitable without credentials. "
                    "Fix: for truly public APIs, * is acceptable. For anything user-specific, "
                    "restrict to a named allowlist of origins."
                )
            ))
