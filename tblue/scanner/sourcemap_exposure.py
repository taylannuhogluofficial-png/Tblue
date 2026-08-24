"""
Source Map Exposure Scanner.

JavaScript source maps (.js.map, .css.map) expose the original unminified
source code, TypeScript, JSX, and internal file paths to anyone who can
access the production server:

  1. Source map referenced in bundle — //# sourceMappingURL= comment in JS
     files pointing to an accessible .map file.

  2. Inline source map — data:application/json;base64,... inline source map
     embeds the full source tree in the JS bundle.

  3. Common source map paths — /static/js/main.js.map, /assets/app.js.map,
     etc. accessible even without the sourceMappingURL comment.

  4. CSS source maps — SCSS/Less source exposed via CSS .map files.

Read-only.

CWE-540: Inclusion of Sensitive Information in Source Code
CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_SOURCE_MAP_COMMENT_RE = re.compile(
    r'//# sourceMappingURL=(?!data:)([^\s\'"<>]+\.map)', re.I
)
_INLINE_MAP_RE = re.compile(
    r'//# sourceMappingURL=data:application/json;base64,', re.I
)

_MAP_PATHS = [
    "/static/js/main.js.map",
    "/static/js/bundle.js.map",
    "/assets/app.js.map",
    "/assets/main.js.map",
    "/js/app.js.map",
    "/dist/bundle.js.map",
    "/build/static/js/main.js.map",
    "/static/css/main.css.map",
]

_JS_PATHS = [
    "/static/js/main.js",
    "/assets/app.js",
    "/js/app.js",
    "/bundle.js",
    "/dist/bundle.js",
]


def _check_inline_sourcemap(body: str, url: str) -> Optional[Dict]:
    if _INLINE_MAP_RE.search(body[:65536]):
        return {
            "type": "sourcemap-inline-in-production",
            "status": "WARN",
            "detail": (
                f"Inline source map found in JavaScript at {url}.\n\n"
                f"Inline source maps embed the full original source code as base64 in "
                f"the production JS bundle, exposing all unminified code, internal paths, "
                f"and developer comments to any visitor.\n\n"
                f"Fix: disable source maps in production builds. In webpack: "
                f"devtool: false. In Vite: build.sourcemap: false."
            ),
        }
    return None


def _check_sourcemap_comment(body: str, base_origin: str, js_url: str, http) -> Optional[Dict]:
    matches = _SOURCE_MAP_COMMENT_RE.findall(body[:65536])
    for map_ref in matches[:3]:
        if map_ref.startswith("http"):
            map_url = map_ref
        else:
            map_url = base_origin + "/" + map_ref.lstrip("/")

        resp = http.get(map_url)
        if resp and resp.status_code == 200 and len(resp.text or "") > 100:
            return {
                "type": "sourcemap-file-publicly-accessible",
                "status": "WARN",
                "detail": (
                    f"Source map file accessible at {map_url} (referenced from {js_url}).\n\n"
                    f"Source maps expose the original unminified source code, file paths, "
                    f"TypeScript types, and internal module structure to anyone who can "
                    f"access the production server.\n\n"
                    f"Fix: either disable source maps in production (recommended), or "
                    f"restrict .map file access via nginx/CDN to authenticated developers only."
                ),
            }
    return None


class SourceMapExposureScanner(BaseScanner):
    """Checks for accessible JavaScript source maps exposing original source code."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Source Map Exposure — target unreachable", "PASS",
                detail="No response; source map exposure check skipped."))
            return self.results

        found = False
        seen_types: set = set()

        # Check well-known .map paths directly
        for path in _MAP_PATHS:
            r = self.http.get(base_origin + path)
            if r and r.status_code == 200 and len(r.text or "") > 50:
                t = "sourcemap-file-publicly-accessible"
                if t not in seen_types:
                    seen_types.add(t)
                    found = True
                    log_warn(logger, f"Source Map Exposure — {t} at {path}")
                    self.results.append(self._result(
                        url, t, "WARN",
                        detail=(
                            f"Source map file accessible at {base_origin + path}.\n\n"
                            f"Source maps expose original unminified source code, file paths, "
                            f"and internal module structure.\n\n"
                            f"Fix: disable source maps in production or restrict .map access."
                        )))

        # Check JS bundles for sourceMappingURL comments
        for path in _JS_PATHS:
            r = self.http.get(base_origin + path)
            if r is None or r.status_code != 200:
                continue
            body = r.text or ""

            f = _check_inline_sourcemap(body, base_origin + path)
            if f and f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                log_warn(logger, f"Source Map Exposure — {f['type']}")
                self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

            f = _check_sourcemap_comment(body, base_origin, base_origin + path, self.http)
            if f and f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                log_warn(logger, f"Source Map Exposure — {f['type']}")
                self.results.append(self._result(url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"Source Map Exposure — no source maps exposed at {url}")
            self.results.append(self._result(
                url, "Source Map Exposure — no accessible source maps found", "PASS",
                detail="No .map files accessible and no inline source maps found in JS bundles."))

        return self.results
