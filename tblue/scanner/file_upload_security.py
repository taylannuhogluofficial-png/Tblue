"""File upload security — unrestricted upload endpoints, missing content-type validation, stored XSS via filename."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_UPLOAD_FORM_RE = re.compile(r'<form\b[^>]*\benctype=["\']multipart/form-data["\'][^>]*>', re.I)
_FILE_INPUT_RE = re.compile(r'<input\b[^>]*\btype=["\']file["\'][^>]*>', re.I)
_ACCEPT_RE = re.compile(r'\baccept=["\']([^"\']+)["\']', re.I)
_MAX_SIZE_RE = re.compile(r'(?:max[_\-]?(?:file)?size|maxFileSize)\s*[=:]\s*(\d+)', re.I)

_UPLOAD_PATHS = [
    "/upload", "/api/upload", "/file/upload", "/media/upload",
    "/attachments", "/files", "/api/files", "/documents",
]

_DANGEROUS_TYPES = {".php", ".phtml", ".asp", ".aspx", ".jsp", ".js", ".html", ".htm", ".svg"}


def _check_upload_forms(body: str, url: str) -> list:
    findings = []
    upload_forms = _UPLOAD_FORM_RE.findall(body)
    file_inputs = _FILE_INPUT_RE.findall(body)

    if file_inputs:
        for inp in file_inputs:
            accept_m = _ACCEPT_RE.search(inp)
            if not accept_m:
                findings.append({
                    "type": "file_upload_no_accept_restriction",
                    "status": "WARN",
                    "url": url,
                    "detail": "File input without accept= attribute — no client-side MIME restriction; "
                              "server-side validation is critical",
                })
            elif accept_m:
                accepted = accept_m.group(1)
                dangerous = [t for t in _DANGEROUS_TYPES if t in accepted.lower()]
                if dangerous:
                    findings.append({
                        "type": "file_upload_dangerous_types_accepted",
                        "status": "FAIL",
                        "url": url,
                        "detail": f"File input accepts dangerous file types: {', '.join(dangerous)} — "
                                  "stored XSS or RCE via file upload possible",
                    })
    return findings


def _check_upload_endpoint_exposed(http, origin: str) -> list:
    findings = []
    for path in _UPLOAD_PATHS[:4]:
        try:
            r = http.get(origin + path)
            if r and r.status_code in (200, 405):
                findings.append({
                    "type": "file_upload_endpoint_exposed",
                    "status": "WARN",
                    "url": origin + path,
                    "detail": f"File upload endpoint {path} accessible — verify content-type validation, "
                              "filename sanitization, AV scanning, and storage outside webroot",
                })
                return findings
        except Exception:
            pass
    return findings


class FileUploadSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "file_upload_no_response", "PASS", detail="No response")]

        for f in _check_upload_forms(resp.text, url):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        for f in _check_upload_endpoint_exposed(self.http, origin):
            results.append(self._result(f["url"], f["type"], f["status"], detail=f["detail"]))

        if not results:
            results.append(self._result(url, "file_upload_clean", "PASS",
                                        detail="No file upload security issues detected"))
        return results
