"""HTTP desync / request tunneling passive detection."""
import re
from .base import BaseScanner

# Indicators that a reverse proxy or load balancer is in play
_PROXY_HEADERS = [
    "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host",
    "via", "x-varnish", "x-cache", "cf-ray", "x-amz-cf-id",
]

# Chunked encoding combined with Content-Length is the CL.TE / TE.CL desync surface
_CL_TE_RE = re.compile(r"transfer-encoding", re.I)


def _check_te_cl_surface(headers: dict, url: str) -> dict | None:
    """If both Content-Length and Transfer-Encoding appear in a response, flag it."""
    has_cl = "content-length" in {k.lower() for k in headers}
    has_te = "transfer-encoding" in {k.lower() for k in headers}
    if has_cl and has_te:
        return {
            "type": "http_desync_te_cl_response",
            "status": "WARN",
            "url": url,
            "detail": "Response contains both Content-Length and Transfer-Encoding — "
                      "may indicate a backend that accepts both, creating desync surface",
        }
    return None


def _check_proxy_chain(headers: dict, url: str) -> dict | None:
    """Multiple proxy hops (Via chains) increase desync risk."""
    via = headers.get("via", "")
    # Count hops: "1.1 proxy1, 1.1 proxy2" → 2 hops
    hops = [h.strip() for h in via.split(",") if h.strip()]
    if len(hops) >= 2:
        return {
            "type": "http_desync_multi_hop_proxy",
            "status": "WARN",
            "url": url,
            "detail": f"Multi-hop proxy chain detected ({len(hops)} Via hops) — "
                      "increases HTTP desync attack surface",
        }
    return None


def _check_frontend_backend_mismatch(headers: dict, url: str) -> dict | None:
    """Inconsistent server headers alongside proxy headers suggest mixed stack."""
    has_proxy = any(h.lower() in {k.lower() for k in headers} for h in _PROXY_HEADERS)
    server = headers.get("server", "").lower()
    if has_proxy and ("nginx" in server or "apache" in server or "iis" in server):
        return {
            "type": "http_desync_mixed_stack",
            "status": "WARN",
            "url": url,
            "detail": f"Proxy headers present with '{server}' origin server — "
                      "classic frontend/backend split susceptible to desync",
        }
    return None


class HTTPDesyncPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "http_desync_no_response", "PASS",
                                 detail="No response")]

        headers = dict(resp.headers)

        te_cl = _check_te_cl_surface(headers, url)
        if te_cl:
            results.append(self._result(te_cl["url"], te_cl["type"], te_cl["status"],
                                        detail=te_cl["detail"]))

        proxy_chain = _check_proxy_chain(headers, url)
        if proxy_chain:
            results.append(self._result(proxy_chain["url"], proxy_chain["type"],
                                        proxy_chain["status"], detail=proxy_chain["detail"]))

        mismatch = _check_frontend_backend_mismatch(headers, url)
        if mismatch:
            results.append(self._result(mismatch["url"], mismatch["type"],
                                        mismatch["status"], detail=mismatch["detail"]))

        if not results:
            results.append(self._result(url, "http_desync_low_risk", "PASS",
                                        detail="No HTTP desync risk indicators detected"))
        return results
