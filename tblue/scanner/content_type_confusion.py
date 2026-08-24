"""Content-Type confusion — MIME sniffing, JSON-as-HTML, JS-as-text/plain, SVG XSS vectors."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_JSON_CONTENT_TYPES = {"application/json", "application/ld+json", "application/problem+json"}
_JS_CONTENT_TYPES = {"application/javascript", "text/javascript", "module"}
_SVG_CONTENT_TYPES = {"image/svg+xml"}
_XML_CONTENT_TYPES = {"application/xml", "text/xml"}

_HTML_SINK_RE = re.compile(r'<(script|iframe|object|embed|link|style)\b', re.I)
_JSON_START_RE = re.compile(r'^\s*[\[{]')

_NOSNIFF_RE = re.compile(r'nosniff', re.I)

_API_PATHS = ["/api/", "/api/v1/", "/api/v2/", "/rest/", "/data/"]


def _get_base_ct(content_type: str) -> str:
    return content_type.split(";")[0].strip().lower() if content_type else ""


def _check_xcto_missing(headers: dict, url: str) -> list:
    xcto = headers.get("x-content-type-options", "")
    if not _NOSNIFF_RE.search(xcto):
        return [{
            "type": "content_type_no_nosniff",
            "status": "WARN",
            "url": url,
            "detail": "X-Content-Type-Options: nosniff is missing — browser may sniff MIME type",
        }]
    return []


def _check_json_served_as_html(body: str, content_type: str, url: str) -> list:
    findings = []
    ct = _get_base_ct(content_type)
    if ct == "text/html" and _JSON_START_RE.match(body):
        findings.append({
            "type": "content_type_json_as_html",
            "status": "WARN",
            "url": url,
            "detail": "JSON response served as text/html — MIME sniffing may allow script execution",
        })
    return findings


def _check_svg_xss_risk(body: str, content_type: str, url: str) -> list:
    ct = _get_base_ct(content_type)
    if ct in _SVG_CONTENT_TYPES and _HTML_SINK_RE.search(body):
        return [{
            "type": "content_type_svg_with_script",
            "status": "FAIL",
            "url": url,
            "detail": "SVG response contains HTML/script tags — user-uploaded SVG can execute scripts in browser",
        }]
    return []


def _check_js_served_incorrectly(content_type: str, url: str) -> list:
    ct = _get_base_ct(content_type)
    if ct == "text/plain" and (url.endswith(".js") or "/js/" in url):
        return [{
            "type": "content_type_js_as_text",
            "status": "WARN",
            "url": url,
            "detail": "JavaScript file served as text/plain — may break module loading or enable MIME confusion",
        }]
    return []


class ContentTypeConfusionScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "content_type_no_response", "PASS",
                                 detail="No response")]

        headers = dict(resp.headers) if resp.headers else {}
        content_type = headers.get("content-type", "")

        for f in _check_xcto_missing(headers, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        for f in _check_json_served_as_html(resp.text, content_type, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        for f in _check_svg_xss_risk(resp.text, content_type, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        for f in _check_js_served_incorrectly(content_type, url):
            results.append(self._result(f["url"], f["type"], f["status"],
                                        detail=f["detail"]))

        if not results:
            results.append(self._result(url, "content_type_clean", "PASS",
                                        detail="Content-Type configuration looks correct"))
        return results
