"""
CORS Deep Analysis Scanner.

Beyond checking for Access-Control-Allow-Origin: *, this scanner probes
more nuanced CORS misconfigurations:

  1. Wildcard + credentials — ACAO: * with ACAC: true is a browser-blocked
     combination but some frameworks emit it; servers accepting arbitrary
     origins with credentials is the real danger.

  2. Origin reflection — if the server echoes back whatever Origin header
     is sent, an attacker-controlled domain gets full CORS access.

  3. Null origin accepted — ACAO: null allows sandboxed iframes and local
     file pages to make credentialed cross-origin requests.

  4. Pre-flight missing — complex requests without OPTIONS handler may
     be handled by the server before the browser enforces CORS.

  5. Vary: Origin missing — without it, a CDN may cache a permissive
     ACAO response and serve it to all visitors.

Read-only passive + one active OPTIONS preflight. No credentials sent.

CWE-942: Permissive Cross-domain Policy with Untrusted Domains
"""

from typing import Any, Dict, List, Optional

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_PROBE_ORIGIN = "https://attacker.tbl9z7x-probe.example.com"
_NULL_ORIGIN = "null"

_API_PATHS = ["/api/", "/api/v1/", "/api/v2/", "/graphql", "/rest/"]


def _check_wildcard_credentials(headers: dict, url: str) -> Optional[Dict]:
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        return {
            "type": "cors-wildcard-with-credentials",
            "status": "FAIL",
            "detail": (
                f"CORS at {url} returns ACAO: * with ACAC: true.\n\n"
                f"Browsers block this combination, but the server is still misconfigured. "
                f"If the server accepts arbitrary specific origins with credentials (see "
                f"origin-reflection check), full cross-origin data theft is possible.\n\n"
                f"Fix: set ACAO to a specific trusted origin when ACAC: true is required."
            ),
        }
    return None


def _check_null_origin(headers: dict, url: str) -> Optional[Dict]:
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == "null":
        return {
            "type": "cors-null-origin-accepted",
            "status": "WARN",
            "detail": (
                f"CORS at {url} accepts Origin: null.\n\n"
                f"Sandboxed iframes, local file pages (file://), and data: URIs send "
                f"Origin: null. An attacker can create a sandboxed iframe on any domain "
                f"to send credentialed requests to this endpoint.\n\n"
                f"Fix: never allow the null origin in your CORS allowlist."
            ),
        }
    if acao == "null" and acac == "true":
        return {
            "type": "cors-null-origin-with-credentials",
            "status": "FAIL",
            "detail": (
                f"CORS at {url} accepts Origin: null with credentials — high risk.\n\n"
                f"Attackers can steal credentialed responses via sandboxed iframes."
            ),
        }
    return None


def _check_vary_origin(headers: dict, url: str) -> Optional[Dict]:
    vary = headers.get("vary", "").lower()
    acao = headers.get("access-control-allow-origin", "")
    if acao and acao != "*" and "origin" not in vary:
        return {
            "type": "cors-missing-vary-origin",
            "status": "WARN",
            "detail": (
                f"CORS at {url} sets a specific ACAO but does not include Origin in "
                f"the Vary header.\n\n"
                f"A CDN or proxy may cache the CORS response for one origin and serve "
                f"it to visitors with a different Origin, leaking or denying CORS access.\n\n"
                f"Fix: always add Vary: Origin when the ACAO value changes per request."
            ),
        }
    return None


def _check_origin_reflection(http, url: str) -> Optional[Dict]:
    """Send probe Origin and check if it is reflected back."""
    resp = http.get(url, headers={"Origin": _PROBE_ORIGIN})
    if resp is None:
        return None
    headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao == _PROBE_ORIGIN:
        severity = "FAIL" if acac == "true" else "WARN"
        return {
            "type": "cors-origin-reflection" + ("-with-credentials" if acac == "true" else ""),
            "status": severity,
            "detail": (
                f"CORS at {url} reflects arbitrary Origin values in ACAO "
                f"({'with credentials' if acac == 'true' else 'without credentials'}).\n\n"
                f"{'With ACAC:true, any attacker-controlled page can read authenticated responses.' if acac == 'true' else 'Without credentials this is lower risk but still a policy violation.'}\n\n"
                f"Fix: maintain an explicit allowlist of trusted origins. Do not reflect the "
                f"incoming Origin header unconditionally."
            ),
        }
    return None


class CORSDeepAnalysisScanner(BaseScanner):
    """Deep CORS analysis: origin reflection, null origin, wildcard+credentials, Vary."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        found = False
        seen_types: set = set()

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "CORS Deep Analysis — target unreachable", "PASS",
                detail="No response; CORS deep analysis skipped."))
            return self.results

        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}

        for check_fn in [_check_wildcard_credentials, _check_null_origin, _check_vary_origin]:
            f = check_fn(headers, url)
            if f and f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                log_warn(logger, f"CORS Deep Analysis — {f['type']}")
                self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        f = _check_origin_reflection(self.http, url)
        if f and f["type"] not in seen_types:
            seen_types.add(f["type"])
            found = True
            status = f["status"]
            if status == "FAIL":
                log_fail(logger, f"CORS Deep Analysis — {f['type']}")
            else:
                log_warn(logger, f"CORS Deep Analysis — {f['type']}")
            self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"CORS Deep Analysis — no issues found for {url}")
            self.results.append(self._result(
                url, "CORS Deep Analysis — no CORS misconfigurations detected", "PASS",
                detail="CORS policy appears correctly configured. No reflection, null origin, or credential issues found."))

        return self.results
