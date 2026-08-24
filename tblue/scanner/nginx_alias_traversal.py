"""Nginx alias traversal detection — off-by-slash misconfiguration and autoindex exposure."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

# Common static file locations that might have alias directives
_STATIC_PATHS = ["/static", "/assets", "/files", "/uploads", "/media", "/images", "/js", "/css"]

_AUTOINDEX_RE = re.compile(r"<title>Index of /", re.I)
_NGINX_RE     = re.compile(r"nginx(?:/[\d.]+)?", re.I)

_ALIAS_TRAVERSAL_SUFFIXES = ["../", "..%2F", "%2e%2e/"]


def _is_nginx(headers: dict) -> bool:
    server = headers.get("server", "")
    return bool(_NGINX_RE.search(server))


def _check_autoindex(http, origin: str, path: str) -> dict | None:
    resp = http.get(origin + path)
    if resp and resp.status_code == 200 and _AUTOINDEX_RE.search(resp.text):
        return {
            "type": "nginx_autoindex_exposure",
            "status": "WARN",
            "url": origin + path,
            "detail": f"Nginx autoindex enabled at {path} — exposes directory listing",
        }
    return None


def _check_alias_traversal(http, origin: str, path: str) -> dict | None:
    # Off-by-slash: if /static serves /var/static/, requesting /static../secret
    # traverses to /var/secret. We detect by comparing status codes.
    baseline_resp = http.get(origin + path + "/")
    if baseline_resp is None or baseline_resp.status_code not in (200, 403):
        return None

    for suffix in _ALIAS_TRAVERSAL_SUFFIXES:
        try:
            probe_url = origin + path + suffix
            r = http.get(probe_url)
            if r and r.status_code == 200 and baseline_resp.status_code == 403:
                return {
                    "type": "nginx_alias_traversal",
                    "status": "FAIL",
                    "url": probe_url,
                    "detail": (
                        f"Nginx alias off-by-slash: {path}/ returns 403 but "
                        f"{path}{suffix} returns 200 — directory traversal possible"
                    ),
                }
        except Exception:
            pass
    return None


class NginxAliasTravesalScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "nginx_alias_traversal_no_response", "PASS",
                                 detail="No response")]

        is_nginx = _is_nginx(resp.headers)
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for path in _STATIC_PATHS:
            auto = _check_autoindex(self.http, origin, path)
            if auto:
                results.append(self._result(auto["url"], auto["type"], auto["status"],
                                            detail=auto["detail"]))

            if is_nginx:
                traversal = _check_alias_traversal(self.http, origin, path)
                if traversal:
                    results.append(self._result(traversal["url"], traversal["type"],
                                                traversal["status"], detail=traversal["detail"]))

        if not results:
            results.append(self._result(url, "nginx_alias_traversal_clean", "PASS",
                                        detail="No Nginx alias traversal or autoindex issues detected"))
        return results
