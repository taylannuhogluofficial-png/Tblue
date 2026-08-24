"""API pagination abuse — missing pagination limits, offset-based mass data extraction, total count disclosure."""
import re
from urllib.parse import urlparse, urlencode
from .base import BaseScanner

_API_PATHS = [
    "/api/users", "/api/v1/users", "/api/items", "/api/v1/items",
    "/api/orders", "/api/products", "/api/data", "/api/v1/data",
    "/api/customers", "/api/records",
]

_TOTAL_COUNT_RE = re.compile(
    r'"(?:total|count|total_count|totalCount|total_results|x-total-count)"\s*:\s*(\d+)',
    re.I,
)
_PAGINATION_RE = re.compile(
    r'"(?:page|offset|limit|per_page|pageSize|cursor|next_page|prev_page)"\s*:',
    re.I,
)
_LARGE_ARRAY_RE = re.compile(r'\[(?:[^[\]]*,){49,}')  # arrays with 50+ commas = 50+ items


def _check_large_default_page(http, origin: str) -> list:
    """Check if API returns huge default pages or no limit enforcement."""
    findings = []
    for path in _API_PATHS[:4]:
        try:
            resp = http.get(origin + path)
            if resp is None or resp.status_code != 200:
                continue
            body = resp.text or ""
            if not body or "<html" in body[:200].lower():
                continue

            m = _TOTAL_COUNT_RE.search(body)
            if m:
                total = int(m.group(1))
                if total > 1000:
                    findings.append({
                        "type": "api_pagination_large_total_disclosed",
                        "status": "WARN",
                        "url": origin + path,
                        "detail": (f"API at {path} discloses total record count of {total:,} — "
                                   f"reveals dataset size; combine with unlimited page size for mass extraction"),
                    })
                    return findings

            if _LARGE_ARRAY_RE.search(body):
                findings.append({
                    "type": "api_pagination_no_limit",
                    "status": "FAIL",
                    "url": origin + path,
                    "detail": (f"API at {path} returns 50+ items in single response without enforced limit — "
                               f"attacker can dump entire dataset without authentication with large ?limit= param"),
                })
                return findings
        except Exception:
            continue
    return findings


def _check_limit_bypass(http, origin: str) -> list:
    """Check if ?limit=99999 bypasses pagination limits."""
    findings = []
    for path in _API_PATHS[:3]:
        try:
            normal = http.get(origin + path)
            if normal is None or normal.status_code != 200:
                continue
            large = http.get(origin + path, params={"limit": "99999", "per_page": "99999"})
            if large is None or large.status_code != 200:
                continue
            normal_len = len(normal.text or "")
            large_len = len(large.text or "")
            if large_len > normal_len * 3 and large_len > 5000:
                findings.append({
                    "type": "api_pagination_limit_bypass",
                    "status": "FAIL",
                    "url": origin + path,
                    "detail": (f"API at {path} returns {large_len} bytes with limit=99999 vs {normal_len} bytes normally — "
                               f"pagination limit not enforced server-side, enabling bulk data extraction"),
                })
                return findings
        except Exception:
            continue
    return findings


class APIPaginationAbuseScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "api_pagination_no_response", "PASS",
                                 detail="No response")]

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for f in _check_large_default_page(self.http, origin):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            for f in _check_limit_bypass(self.http, origin):
                results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "api_pagination_clean", "PASS",
                                        detail="No API pagination abuse indicators detected"))
        return results
