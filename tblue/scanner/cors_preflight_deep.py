"""CORS preflight deep — wildcard with credentials, missing Vary, preflight cache abuse."""
import re
from .base import BaseScanner

_PROBE_ORIGIN = "https://attacker-tbl9z7x-cors.example.com"
_PROBE_METHOD = "DELETE"
_PROBE_HEADER = "X-Custom-Header"

_ACAO_RE = re.compile(r'access-control-allow-origin', re.I)
_ACAC_RE = re.compile(r'access-control-allow-credentials', re.I)
_ACAM_RE = re.compile(r'access-control-allow-methods', re.I)
_ACAH_RE = re.compile(r'access-control-allow-headers', re.I)
_ACMA_RE = re.compile(r'access-control-max-age', re.I)
_VARY_RE = re.compile(r'vary', re.I)


def _send_preflight(http, url: str) -> dict | None:
    try:
        resp = http.get(url, headers={
            "Origin": _PROBE_ORIGIN,
            "Access-Control-Request-Method": _PROBE_METHOD,
            "Access-Control-Request-Headers": _PROBE_HEADER,
        })
        return resp
    except Exception:
        return None


def _check_cors_preflight_response(headers: dict, url: str) -> list:
    findings = []
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    acam = headers.get("access-control-allow-methods", "")
    vary = headers.get("vary", "")

    if acao == "*" and acac.lower() == "true":
        findings.append({
            "type": "cors_preflight_wildcard_with_credentials",
            "status": "FAIL",
            "url": url,
            "detail": "CORS: Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true — "
                      "browsers reject this but misconfigured stacks may process it",
        })

    if _PROBE_ORIGIN in acao and acac.lower() == "true":
        findings.append({
            "type": "cors_preflight_reflected_with_credentials",
            "status": "FAIL",
            "url": url,
            "detail": f"CORS preflight reflects attacker origin ({_PROBE_ORIGIN}) with credentials=true — "
                      "full CORS bypass, attacker JS can make credentialed cross-origin requests",
        })

    if _PROBE_ORIGIN in acao and "origin" not in vary.lower():
        findings.append({
            "type": "cors_preflight_missing_vary_origin",
            "status": "WARN",
            "url": url,
            "detail": "CORS: Origin reflected in ACAO but Vary: Origin missing — "
                      "response may be cached with wrong ACAO, enabling CORS cache poisoning",
        })

    dangerous = [m for m in re.split(r'[\s,]+', acam) if m.upper() in ("DELETE", "PUT", "PATCH")]
    if dangerous and _PROBE_ORIGIN in acao:
        findings.append({
            "type": "cors_preflight_dangerous_methods_allowed",
            "status": "WARN",
            "url": url,
            "detail": f"CORS allows dangerous methods to attacker origin: {', '.join(dangerous)}",
        })

    return findings


class CORSPreflightDeepScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "cors_preflight_no_response", "PASS", detail="No response")]

        preflight = _send_preflight(self.http, url)
        if preflight is None:
            return [self._result(url, "cors_preflight_no_response", "PASS", detail="No response")]

        headers = dict(preflight.headers) if preflight.headers else {}
        for f in _check_cors_preflight_response(headers, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "cors_preflight_clean", "PASS",
                                        detail="CORS preflight configuration looks safe"))
        return results
