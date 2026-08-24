"""API pagination security — missing limits, excessive data exposure, cursor leakage."""
import re
import json
from urllib.parse import urlparse, urlencode, urljoin
from .base import BaseScanner

_API_PROBE_PATHS = [
    "/api/users", "/api/user", "/api/items", "/api/products",
    "/api/orders", "/api/list", "/api/v1/users", "/api/v2/users",
]

_LARGE_RESPONSE_THRESHOLD = 50_000  # 50KB in a JSON response is suspicious
_CURSOR_PARAM_RE = re.compile(r"(?:cursor|page_token|next_token|after|before)\b", re.I)
_TOTAL_COUNT_RE  = re.compile(r'"(?:total|count|total_count|totalCount)"\s*:\s*(\d+)', re.I)


def _check_pagination_missing(http, base_url: str, path: str) -> list:
    findings = []
    url = base_url + path
    try:
        r = http.get(url)
        if r is None or r.status_code not in (200, 201):
            return findings

        body = r.text
        ct = r.headers.get("content-type", "")
        if "json" not in ct.lower():
            return findings

        # Large JSON response without pagination headers
        content_len = len(body)
        if content_len > _LARGE_RESPONSE_THRESHOLD:
            has_link = "link" in {k.lower() for k in r.headers}
            has_x_total = any(k.lower().startswith("x-total") for k in r.headers)
            if not has_link and not has_x_total:
                findings.append({
                    "type": "api_pagination_missing",
                    "status": "WARN",
                    "url": url,
                    "detail": f"Large API response ({content_len} bytes) at {path} without "
                              "pagination headers (Link / X-Total-Count) — possible mass data exposure",
                })

        # High total count without size limit
        match = _TOTAL_COUNT_RE.search(body)
        if match:
            total = int(match.group(1))
            if total > 1000:
                findings.append({
                    "type": "api_excessive_data_count",
                    "status": "WARN",
                    "url": url,
                    "detail": f"API endpoint {path} reports {total:,} total records — "
                              "verify server-side row limits are enforced",
                })

        # Check if limit=0 or limit=99999 disables pagination
        for limit_val in ["0", "99999", "999999"]:
            probe = http.get(url + f"?limit={limit_val}")
            if probe and probe.status_code == 200 and len(probe.text) > _LARGE_RESPONSE_THRESHOLD:
                findings.append({
                    "type": "api_pagination_bypass",
                    "status": "FAIL",
                    "url": url + f"?limit={limit_val}",
                    "detail": f"API at {path} returns large response with limit={limit_val} — "
                              "server-side pagination limit not enforced",
                })
                break

    except Exception:
        pass
    return findings


class APIPaginationSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "api_pagination_no_response", "PASS",
                                 detail="No response")]

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for path in _API_PROBE_PATHS:
            for finding in _check_pagination_missing(self.http, origin, path):
                results.append(self._result(finding["url"], finding["type"],
                                            finding["status"], detail=finding["detail"]))

        if not results:
            results.append(self._result(url, "api_pagination_clean", "PASS",
                                        detail="No API pagination security issues detected"))
        return results
