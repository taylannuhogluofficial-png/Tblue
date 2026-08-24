"""HTTP parameter pollution — duplicate parameters accepted, last/first-wins discrepancy, array injection."""
import re
from urllib.parse import urlparse, parse_qs, urlencode
from .base import BaseScanner

_PARAM_POLLUTION_PROBE_A = "tbl9z7x-appa"
_PARAM_POLLUTION_PROBE_B = "tbl9z7x-appb"

_FORM_PARAMS_RE = re.compile(
    r'<input\b[^>]*\bname=["\']([^"\']+)["\'][^>]*>', re.I
)
_QUERY_PARAM_RE = re.compile(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', re.I)


def _check_duplicate_params_reflected(http, url: str) -> list:
    """Send duplicate parameter and check which value is reflected — indicates HPP."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    # Find existing params or use 'id' as probe
    existing = list(parse_qs(parsed.query).keys())
    probe_param = existing[0] if existing else "id"

    try:
        probe_url = (f"{base}?{probe_param}={_PARAM_POLLUTION_PROBE_A}"
                     f"&{probe_param}={_PARAM_POLLUTION_PROBE_B}")
        resp = http.get(probe_url)
        if resp is None:
            return findings

        body = resp.text or ""
        has_a = _PARAM_POLLUTION_PROBE_A in body
        has_b = _PARAM_POLLUTION_PROBE_B in body

        if has_a and has_b:
            findings.append({
                "type": "parameter_pollution_both_values",
                "status": "WARN",
                "url": probe_url,
                "detail": f"Both duplicate parameter values reflected — server concatenates ?{probe_param}= "
                          "values; may confuse access control or validation logic",
            })
        elif has_b and not has_a:
            findings.append({
                "type": "parameter_pollution_last_wins",
                "status": "WARN",
                "url": probe_url,
                "detail": f"Last duplicate parameter value wins for ?{probe_param}= — "
                          "attackers can override first value by appending second",
            })
    except Exception:
        pass
    return findings


def _check_array_parameter_injection(http, url: str) -> list:
    """Send array-style parameters and check if server processes them."""
    findings = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    try:
        probe_url = f"{base}?id[]={_PARAM_POLLUTION_PROBE_A}&id[]={_PARAM_POLLUTION_PROBE_B}"
        resp = http.get(probe_url)
        if resp and resp.status_code == 200:
            body = resp.text or ""
            if _PARAM_POLLUTION_PROBE_A in body or _PARAM_POLLUTION_PROBE_B in body:
                findings.append({
                    "type": "parameter_pollution_array_injection",
                    "status": "WARN",
                    "url": probe_url,
                    "detail": "Server processes array-style parameters (id[]=...) — "
                              "may enable bypassing single-value validation",
                })
    except Exception:
        pass
    return findings


class ParameterPollutionScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "param_pollution_no_response", "PASS", detail="No response")]

        for f in _check_duplicate_params_reflected(self.http, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        for f in _check_array_parameter_injection(self.http, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "param_pollution_clean", "PASS",
                                        detail="No HTTP parameter pollution indicators detected"))
        return results
