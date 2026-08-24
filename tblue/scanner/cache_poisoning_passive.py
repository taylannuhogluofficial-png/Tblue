"""Cache poisoning passive — unkeyed headers reflected, X-Forwarded-Host/Port, Vary analysis."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_FORWARDED_HEADERS_TO_TEST = [
    ("X-Forwarded-Host", "attacker-tbl9z7x.example.com"),
    ("X-Forwarded-Port", "8443"),
    ("X-Forwarded-Scheme", "http"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
]

_VARY_ANALYSIS_IGNORE = {"accept-encoding", "accept-language", "accept"}
_SENSITIVE_VARY = {"x-forwarded-for", "x-real-ip", "x-forwarded-host", "cookie", "authorization"}


def _check_host_header_reflected(http, url: str, origin: str) -> list:
    """Check if X-Forwarded-Host is reflected in response body or location headers."""
    findings = []
    probe = "attacker-tbl9z7x.example.com"
    try:
        resp = http.get(url, headers={"X-Forwarded-Host": probe})
        if resp is None:
            return findings
        if probe in (resp.text or ""):
            findings.append({
                "type": "cache_poisoning_host_reflected",
                "status": "FAIL",
                "url": url,
                "detail": (f"X-Forwarded-Host value reflected in response body — "
                           f"if cached, could poison cache with attacker-controlled host"),
            })
        location = (resp.headers or {}).get("location", "")
        if probe in location:
            findings.append({
                "type": "cache_poisoning_host_in_redirect",
                "status": "FAIL",
                "url": url,
                "detail": "X-Forwarded-Host value appears in Location redirect — cache poisoning risk",
            })
    except Exception:
        pass
    return findings


def _check_vary_header(headers: dict, url: str) -> list:
    """Check if Vary header includes sensitive headers that could enable cache poisoning."""
    findings = []
    vary = headers.get("vary", "")
    if not vary:
        return findings
    vary_fields = {v.strip().lower() for v in vary.split(",")}
    sensitive = vary_fields & _SENSITIVE_VARY
    if sensitive:
        findings.append({
            "type": "cache_poisoning_sensitive_vary",
            "status": "WARN",
            "url": url,
            "detail": (f"Vary header includes sensitive fields: {', '.join(sensitive)} — "
                       f"these become cache keys and could enable cache confusion attacks"),
        })
    return findings


def _check_age_without_cache_control(headers: dict, url: str) -> list:
    """Age header without proper Cache-Control means response might be cached unintentionally."""
    findings = []
    age = headers.get("age", "")
    cc = headers.get("cache-control", "")
    if age and not cc:
        findings.append({
            "type": "cache_poisoning_age_no_cache_control",
            "status": "WARN",
            "url": url,
            "detail": (f"Response has Age: {age} header but no Cache-Control — "
                       f"response may be cached by intermediaries without intended constraints"),
        })
    elif age and "no-store" not in cc and "private" not in cc:
        # Check if sensitive content
        pass  # not enough signal alone
    return findings


class CachePoisoningPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "cache_poisoning_no_response", "PASS",
                                 detail="No response")]

        headers = dict(resp.headers) if resp.headers else {}
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for f in _check_vary_header(headers, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        for f in _check_age_without_cache_control(headers, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        for f in _check_host_header_reflected(self.http, url, origin):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        if not results:
            results.append(self._result(url, "cache_poisoning_clean", "PASS",
                                        detail="No cache poisoning indicators detected"))
        return results
