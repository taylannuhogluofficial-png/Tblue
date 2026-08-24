"""Source map exposure — .js.map files exposed, paths revealing server structure, source disclosure."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_SOURCE_MAP_COMMENT_RE = re.compile(
    r'//[#@]\s*sourceMappingURL=([^\s"\'<>]+\.map)',
    re.I,
)
_SOURCE_MAP_HEADER_RE = re.compile(r'sourcemap|x-sourcemap', re.I)

_JS_PATHS_TO_CHECK = [
    "/static/js/main.js", "/static/js/bundle.js", "/js/app.js",
    "/assets/js/app.js", "/dist/bundle.js", "/app.js",
]

_SERVER_PATH_RE = re.compile(
    r'(?:/(?:home|srv|app|opt|var/www|usr/local)/[a-zA-Z0-9_/\\.]+\.(?:js|ts|jsx|tsx))',
    re.I,
)
_WEBPACK_RE = re.compile(r'webpack://|/node_modules/', re.I)


def _check_source_map_comment(body: str, base_url: str) -> list:
    findings = []
    for m in _SOURCE_MAP_COMMENT_RE.finditer(body):
        map_ref = m.group(1)
        findings.append({
            "type": "source_map_comment_exposed",
            "status": "WARN",
            "url": base_url,
            "detail": f"Source map reference found: {map_ref} — if accessible, reveals original source code",
        })
    return findings


def _check_map_file_accessible(http, js_url: str) -> list:
    """Check if the .map file for a JS file is actually downloadable."""
    findings = []
    map_url = js_url + ".map"
    try:
        r = http.get(map_url)
        if r and r.status_code == 200 and len(r.text or "") > 100:
            body = r.text
            severity = "FAIL" if _SERVER_PATH_RE.search(body) or _WEBPACK_RE.search(body) else "WARN"
            findings.append({
                "type": "source_map_file_accessible",
                "status": severity,
                "url": map_url,
                "detail": f"Source map file downloadable at {map_url} — "
                          "original source code, server paths, and logic are exposed",
            })
    except Exception:
        pass
    return findings


class SourceMapExposureScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "source_map_no_response", "PASS", detail="No response")]

        for f in _check_source_map_comment(resp.text, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for path in _JS_PATHS_TO_CHECK[:3]:
            r = self.http.get(origin + path)
            if r and r.status_code == 200:
                for f in _check_source_map_comment(r.text, origin + path):
                    results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))
                for f in _check_map_file_accessible(self.http, origin + path):
                    results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "source_map_clean", "PASS",
                                        detail="No source map exposure detected"))
        return results
