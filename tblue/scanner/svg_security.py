"""
SVG Security Scanner.

Scalable Vector Graphics (SVG) files are a distinct attack surface because SVG
is XML that supports embedded scripts, event handlers, and cross-origin references.
When SVGs are served inline or as images, they can bypass CSP and SRI protections.

Security issues:

1. SVG served without Content-Disposition: attachment:
   - Browsers that render SVG inline can execute <script> inside the SVG.
   - When served as image/svg+xml without attachment disposition, inline scripts run.
2. SVG with embedded <script> element:
   - Direct code execution inside SVG when loaded in an img-like context or inline.
3. SVG with event handler attributes (onload, onclick, onmouseover):
   - `<svg onload="alert(1)">` — fires when the SVG is rendered.
4. SVG with <foreignObject>:
   - Allows arbitrary HTML inside SVG — a common SVG-based XSS bypass.
5. SVG with <use> referencing external hrefs:
   - `<use href="https://evil.com/sprite.svg#icon">` — cross-origin resource load.
6. SVG served as text/html:
   - Browsers parse SVG as HTML, executing any script content.
7. SVG with SMIL animation event handlers:
   - <animate onbegin="..."> fires JavaScript from animation timelines.
8. SVG uploaded to user-controlled paths without sanitization indicators.
9. MIME type mismatch: SVG content but non-SVG Content-Type.

CWE-79: Cross-site Scripting
CWE-116: Improper Encoding or Escaping of Output
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_SVG_PATHS = [
    "/logo.svg", "/icon.svg", "/images/logo.svg", "/assets/logo.svg",
    "/static/logo.svg", "/img/logo.svg", "/favicon.svg",
    "/icons/sprite.svg", "/assets/icons.svg", "/public/logo.svg",
]

_SVG_SCRIPT_RE     = re.compile(r'<script\b', re.I)
_SVG_EVENT_RE      = re.compile(r'\bon(?:load|click|mouseover|mouseout|error|focus|blur|begin|end|repeat)\s*=\s*["\']', re.I)
_SVG_FOREIGN_RE    = re.compile(r'<foreignObject\b', re.I)
_SVG_USE_EXT_RE    = re.compile(r'<use\b[^>]*\bhref\s*=\s*["\']https?://', re.I)
_SVG_ANIMATE_EV_RE = re.compile(r'<animate\b[^>]*\bon(?:begin|end|repeat)\s*=', re.I)

_UPLOAD_PATH_RE = re.compile(
    r'(?:upload|media|user[_-]?content|avatar|profile|attachment|files|storage)',
    re.I
)


def _is_svg_content(resp) -> bool:
    ct = ""
    if hasattr(resp.headers, "get"):
        ct = resp.headers.get("content-type", "")
    elif isinstance(resp.headers, dict):
        ct = resp.headers.get("content-type", resp.headers.get("Content-Type", ""))
    return "svg" in ct.lower()


def _has_cd_attachment(resp) -> bool:
    cd = ""
    if hasattr(resp.headers, "get"):
        cd = resp.headers.get("content-disposition", "")
    elif isinstance(resp.headers, dict):
        cd = resp.headers.get("content-disposition", resp.headers.get("Content-Disposition", ""))
    return "attachment" in cd.lower()


class SVGSecurityScanner(BaseScanner):
    """Detect SVG-based security issues: inline scripts, event handlers, foreignObject."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0
        checked_svg = False

        # Check well-known SVG paths
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

        for path in _SVG_PATHS:
            if findings >= 8:
                break
            svg_url = base + path
            try:
                resp = self.http.get(svg_url)
            except Exception:
                continue

            if resp is None or resp.status_code not in (200,):
                continue
            if not _is_svg_content(resp):
                continue

            checked_svg = True
            body = resp.text or ""

            # Script inside SVG
            if _SVG_SCRIPT_RE.search(body):
                log_fail(logger, f"SVG with embedded <script> at {svg_url}")
                self.results.append(self._result(
                    url,
                    f"SVG security — embedded <script> in SVG: {path}",
                    "FAIL",
                    detail=(
                        f"The SVG at '{path}' contains an embedded <script> element. "
                        "When this SVG is loaded inline or as a standalone document, "
                        "the script executes in the page's origin. "
                        "Fix: strip scripts from SVG files using a sanitizer; serve "
                        "user-uploaded SVGs with Content-Disposition: attachment."
                    )
                ))
                findings += 1

            # Event handler attributes
            ev_m = _SVG_EVENT_RE.search(body)
            if ev_m:
                log_fail(logger, f"SVG with event handler at {svg_url}")
                self.results.append(self._result(
                    url,
                    f"SVG security — event handler attribute in SVG: {path}",
                    "FAIL",
                    detail=(
                        f"The SVG at '{path}' contains event handler attributes "
                        "(onload, onclick, onmouseover, etc.). These execute JavaScript "
                        "when the SVG is rendered. "
                        "Fix: sanitize SVG files to remove all event handler attributes."
                    )
                ))
                findings += 1

            # foreignObject
            if _SVG_FOREIGN_RE.search(body):
                log_warn(logger, f"SVG with <foreignObject> at {svg_url}")
                self.results.append(self._result(
                    url,
                    f"SVG security — <foreignObject> in SVG: {path}",
                    "WARN",
                    detail=(
                        f"The SVG at '{path}' uses <foreignObject>, which embeds arbitrary "
                        "HTML inside SVG. When the SVG is rendered inline, the foreign HTML "
                        "is parsed by the browser and can contain scripts or links. "
                        "Fix: reject SVGs containing <foreignObject> in user uploads; "
                        "sanitize SVG files before serving."
                    )
                ))
                findings += 1

            # External use href
            if _SVG_USE_EXT_RE.search(body):
                log_warn(logger, f"SVG <use> external href at {svg_url}")
                self.results.append(self._result(
                    url,
                    f"SVG security — <use href> points to external URL: {path}",
                    "WARN",
                    detail=(
                        f"The SVG at '{path}' has a <use href='https://...#...'>  element "
                        "referencing an external SVG resource. External SVG references can "
                        "be used to load malicious sprites or leak document state. "
                        "Fix: only allow relative or same-origin <use> references."
                    )
                ))
                findings += 1

            # Animated event handlers
            if _SVG_ANIMATE_EV_RE.search(body):
                log_warn(logger, f"SVG SMIL animate event handler at {svg_url}")
                self.results.append(self._result(
                    url,
                    f"SVG security — SMIL animation event handler in SVG: {path}",
                    "WARN",
                    detail=(
                        f"The SVG at '{path}' uses SMIL animation elements with event "
                        "handler attributes (onbegin, onend, onrepeat). These fire JavaScript "
                        "from animation lifecycle events. "
                        "Fix: disable SMIL or sanitize animation event handlers."
                    )
                ))
                findings += 1

            # SVG without Content-Disposition: attachment
            if not _has_cd_attachment(resp) and _UPLOAD_PATH_RE.search(path):
                log_warn(logger, f"SVG on upload path without attachment disposition at {svg_url}")
                self.results.append(self._result(
                    url,
                    f"SVG security — user-upload path SVG served without attachment disposition: {path}",
                    "WARN",
                    detail=(
                        f"SVG at '{path}' (likely user-uploaded) is served as image/svg+xml "
                        "without Content-Disposition: attachment. If this SVG contains scripts "
                        "or event handlers, browsers will execute them. "
                        "Fix: serve user-uploaded SVGs with Content-Disposition: attachment."
                    )
                ))
                findings += 1

        if not checked_svg:
            log_pass(logger, f"No accessible SVG files found at {url}")
            self.results.append(self._result(
                url, "SVG security — no accessible SVG files found", "PASS",
                detail="No SVG files found at common paths. SVG-based attack surface minimal."
            ))
        elif not self.results:
            log_pass(logger, f"SVG files appear clean at {url}")
            self.results.append(self._result(
                url, "SVG security — accessible SVG files appear clean", "PASS",
                detail="SVG files found but contain no embedded scripts, event handlers, or foreignObject."
            ))

        return self.results
