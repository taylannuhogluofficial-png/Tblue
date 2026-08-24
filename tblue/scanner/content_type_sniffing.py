"""Content-type sniffing — MIME type confusion attacks, missing nosniff, polyglot file risks."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_UPLOAD_PATHS = [
    "/uploads/", "/upload/", "/files/", "/static/uploads/",
    "/media/", "/attachments/", "/assets/uploads/",
    "/public/uploads/", "/user-content/", "/ugc/",
]

_SCRIPT_MIME_RE = re.compile(
    r'content-type\s*:\s*(?:application/javascript|text/javascript|text/ecmascript)',
    re.I,
)

_SNIFFABLE_MIMES = {
    "text/plain": "Can be sniffed as HTML/JS if content looks like it",
    "application/octet-stream": "Browsers may sniff MIME from content — serves as attack vector for file uploads",
    "image/svg+xml": "SVG can contain scripts — must serve with nosniff and CSP",
}

_XCTO_MISSING_RE = re.compile(r'x-content-type-options', re.I)

_HTML_IN_JSON_RE = re.compile(r'<(?:script|img|svg|iframe)\b', re.I)

_POLYGLOT_INDICATORS_RE = re.compile(
    r'(?:%PDF-|GIF89a|PNG\r\n|JFIF|Exif\x00\x00)',
    re.I,
)


def _get_header(headers, name: str) -> str:
    if hasattr(headers, "get"):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    if isinstance(headers, dict):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    return ""


def _check_json_with_html(http, url: str) -> list:
    """Check API endpoints that return JSON but may contain HTML/script injection."""
    findings = []
    try:
        resp = http.get(url)
        if resp is None or resp.status_code != 200:
            return findings
        ct = _get_header(resp.headers, "content-type")
        body = resp.text or ""
        xcto = _get_header(resp.headers, "x-content-type-options")

        if "json" in ct.lower() and _HTML_IN_JSON_RE.search(body):
            if not xcto or "nosniff" not in xcto.lower():
                findings.append({
                    "type": "content_sniffing_html_in_json",
                    "status": "WARN",
                    "url": url,
                    "detail": ("JSON response contains HTML tags without X-Content-Type-Options: nosniff — "
                               "older browsers may render as HTML; set nosniff on all JSON responses"),
                })
    except Exception:
        pass
    return findings


def _check_upload_endpoint_sniffing(http, origin: str) -> list:
    """Check if upload endpoints serve files without nosniff."""
    findings = []
    for path in _UPLOAD_PATHS[:3]:
        try:
            resp = http.get(origin + path)
            if resp is None or resp.status_code not in (200, 403):
                continue
            xcto = _get_header(resp.headers, "x-content-type-options")
            ct = _get_header(resp.headers, "content-type")

            if not xcto or "nosniff" not in xcto.lower():
                if resp.status_code == 200:
                    finding_msg = (f"Upload/file serving path {path} accessible without "
                                   f"X-Content-Type-Options: nosniff — "
                                   f"uploaded files may be served with sniffable MIME types, enabling script execution")
                    if "text/plain" in ct or "octet-stream" in ct:
                        finding_msg += f" (Content-Type: {ct!r} is particularly sniffable)"
                    findings.append({
                        "type": "content_sniffing_upload_no_nosniff",
                        "status": "WARN",
                        "url": origin + path,
                        "detail": finding_msg,
                    })
                    return findings
        except Exception:
            pass
    return findings


class ContentTypeSniffingScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "content_sniffing_no_response", "PASS",
                                 detail="No response")]

        xcto = _get_header(resp.headers, "x-content-type-options")
        ct = _get_header(resp.headers, "content-type")

        if not xcto or "nosniff" not in xcto.lower():
            base_ct = ct.split(";")[0].strip().lower() if ct else ""
            if base_ct in _SNIFFABLE_MIMES:
                results.append(self._result(url, "content_sniffing_risky_mime_no_nosniff", "WARN",
                                            detail=(f"Content-Type: {base_ct!r} without X-Content-Type-Options: nosniff — "
                                                    f"{_SNIFFABLE_MIMES[base_ct]}")))
            elif "text/html" not in base_ct and base_ct:
                results.append(self._result(url, "content_sniffing_nosniff_missing", "WARN",
                                            detail="X-Content-Type-Options: nosniff missing — "
                                                   "browsers may MIME-sniff this response"))

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for f in _check_json_with_html(self.http, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        for f in _check_upload_endpoint_sniffing(self.http, origin):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "content_sniffing_clean", "PASS",
                                        detail="No content-type sniffing vulnerabilities detected"))
        return results
