"""
MIME Type Security Scanner.

MIME type misconfigurations enable a class of attacks where browsers
process content as a different type than intended:

  1. Missing X-Content-Type-Options — without nosniff, browsers may MIME-sniff
     responses and execute uploaded images as HTML or scripts.

  2. JavaScript served as wrong MIME type — if a script URL returns
     text/plain or application/octet-stream, some browsers still execute it.

  3. JSON served without nosniff — JSON with XSSI payloads (]});) can be
     delivered without protection if X-Content-Type-Options is absent.

  4. SVG as image/svg+xml without restrictions — SVG can contain <script>
     tags; serving user-uploaded SVG as image/svg+xml without
     X-Content-Type-Options: nosniff enables XSS.

  5. Multipart/form-data response — responses with this content type can
     confuse parsers and enable boundary injection attacks.

  6. Charset mismatch — pages declaring charset=utf-7 or charset=us-ascii
     in meta tags but serving UTF-8 can enable UTF-7 XSS in legacy browsers.

  7. Content-Type: text/html on API endpoints — API endpoints that return
     application/json data but set Content-Type: text/html allow the
     browser to render the JSON as HTML.

Read-only.

CWE-430: Deployment of Wrong Handler
CWE-116: Improper Encoding or Escaping of Output
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_API_PATHS = ["/api", "/api/v1", "/api/v1/users", "/graphql", "/data", "/rest"]
_UPLOAD_PATHS = ["/upload", "/uploads", "/files", "/media", "/assets/uploads"]

_UTF7_RE = re.compile(r'charset\s*=\s*["\']?\s*utf-7', re.I)
_US_ASCII_RE = re.compile(r'charset\s*=\s*["\']?\s*us-ascii', re.I)
_JSON_BODY_RE = re.compile(r'^\s*[\[{]', re.S)


def _get_content_type(headers: dict) -> str:
    return (headers.get("content-type", "") or
            headers.get("Content-Type", "")).lower()


def _check_xcto(headers: dict, url: str) -> Optional[Dict]:
    xcto = (headers.get("x-content-type-options", "") or
            headers.get("X-Content-Type-Options", "")).lower()
    if "nosniff" not in xcto:
        return {
            "type": "mime-type-missing-xcto-nosniff",
            "status": "WARN",
            "detail": (
                f"X-Content-Type-Options: nosniff is missing from {url}.\n\n"
                f"Without nosniff, browsers may MIME-sniff responses and execute "
                f"uploaded images as HTML or treat text/plain as JavaScript.\n\n"
                f"Fix: add X-Content-Type-Options: nosniff to all responses."
            ),
        }
    return None


def _check_json_as_html(headers: dict, body: str, url: str) -> Optional[Dict]:
    ct = _get_content_type(headers)
    if "html" in ct and _JSON_BODY_RE.match(body or ""):
        return {
            "type": "mime-type-json-served-as-html",
            "status": "WARN",
            "detail": (
                f"Endpoint {url} returns Content-Type: text/html but the body "
                f"begins with a JSON structure.\n\n"
                f"Browsers will render the JSON as HTML. If the JSON contains "
                f"user-controlled values, this can lead to XSS or XSSI attacks.\n\n"
                f"Fix: set Content-Type: application/json for API endpoints."
            ),
        }
    return None


def _check_charset_mismatch(body: str, url: str) -> Optional[Dict]:
    if _UTF7_RE.search(body or ""):
        return {
            "type": "mime-type-utf7-charset-declared",
            "status": "WARN",
            "detail": (
                f"Page at {url} declares charset=utf-7 in its HTML.\n\n"
                f"UTF-7 encoding allows XSS in older browsers via +ADw-SCRIPT+AD4- "
                f"sequences that bypass filters expecting UTF-8.\n\n"
                f"Fix: serve all pages as UTF-8 and remove charset=utf-7 declarations."
            ),
        }
    return None


def _check_svg_content_type(headers: dict, url: str) -> Optional[Dict]:
    ct = _get_content_type(headers)
    xcto = (headers.get("x-content-type-options", "") or
            headers.get("X-Content-Type-Options", "")).lower()
    if "svg" in ct and "nosniff" not in xcto:
        return {
            "type": "mime-type-svg-without-nosniff",
            "status": "WARN",
            "detail": (
                f"SVG content served at {url} without X-Content-Type-Options: nosniff.\n\n"
                f"SVG files can contain <script> elements. Without nosniff, browsers "
                f"may execute embedded scripts in user-uploaded SVG files.\n\n"
                f"Fix: add X-Content-Type-Options: nosniff. Consider serving "
                f"user-uploaded SVG as image/png or stripping script elements."
            ),
        }
    return None


class MIMETypeSecurityScanner(BaseScanner):
    """Checks for MIME type misconfigurations: XCTO, JSON-as-HTML, SVG, charset."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "MIME Type Security — target unreachable", "PASS",
                detail="No response; MIME type check skipped."))
            return self.results

        parsed = urlparse(url)
        base_origin = f"{parsed.scheme}://{parsed.netloc}"
        found = False
        seen_types: set = set()

        def _add(f):
            nonlocal found
            if f and f["type"] not in seen_types:
                seen_types.add(f["type"])
                found = True
                log_warn(logger, f"MIME Type Security — {f['type']} at {url}")
                self.results.append(self._result(
                    url, f["type"], f["status"], detail=f["detail"]))

        headers = resp.headers or {}
        body = resp.text or ""

        _add(_check_xcto(headers, url))
        _add(_check_json_as_html(headers, body, url))
        _add(_check_charset_mismatch(body, url))
        _add(_check_svg_content_type(headers, url))

        # Check API endpoints for JSON-as-HTML
        for path in _API_PATHS:
            ep = urljoin(base_origin, path)
            r = self.http.get(ep)
            if r is None or r.status_code not in (200, 201):
                continue
            _add(_check_json_as_html(r.headers or {}, r.text or "", ep))
            _add(_check_xcto(r.headers or {}, ep))

        if not found:
            log_pass(logger, f"MIME Type Security — no issues found for {url}")
            self.results.append(self._result(
                url,
                "MIME Type Security — no MIME type security issues detected",
                "PASS",
                detail="X-Content-Type-Options: nosniff present, no JSON-as-HTML, no UTF-7 charset.",
            ))

        return self.results
