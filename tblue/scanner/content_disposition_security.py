"""
Content-Disposition Security Scanner.

The Content-Disposition response header controls whether the browser renders
a resource inline or prompts the user to download it. Misconfigurations enable:

1. Inline rendering of dangerous MIME types:
   - HTML served inline from untrusted-upload endpoints executes JavaScript in
     the site's origin — same-origin stored XSS.
   - SVG served inline executes embedded JavaScript (SVG is a scriptable format).
   - PDF served inline without Content-Security-Policy can execute JavaScript via
     form fields or JavaScript PDF actions.
2. Missing Content-Disposition: attachment on user-uploaded file downloads:
   - Without `attachment`, the browser renders files inline based on Content-Type
     sniffing (even if X-Content-Type-Options: nosniff is set on different path).
3. Filename path traversal:
   - `Content-Disposition: attachment; filename="../../etc/passwd"` — although
     modern browsers sanitize this, it may confuse downstream parsers.
4. UTF-7 / Unicode shenanigans in filename parameter:
   - `filename*=UTF-8''%e2%80%ae...` — right-to-left override in filename can
     trick users into opening executables with document extensions.
5. Content-Disposition missing on API error responses that include HTML:
   - Enables reflected/stored XSS via API error message rendering.
6. `Content-Disposition: attachment` with dangerous filename extension:
   - `.exe`, `.bat`, `.scr` served as attachments on a trusted domain.

CWE-116: Improper Encoding or Escaping of Output
CWE-434: Unrestricted Upload of File with Dangerous Type
CWE-79: Cross-Site Scripting
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_INLINE_DANGEROUS_CT = re.compile(
    r'(?:text/html|image/svg\+xml|application/xhtml\+xml|text/xml|application/xml)',
    re.I
)
_INLINE_PDF_CT       = re.compile(r'application/pdf', re.I)
_SCRIPT_CT           = re.compile(r'(?:text/javascript|application/javascript|application/ecmascript)', re.I)

_CD_FILENAME_RE      = re.compile(r'filename\s*=\s*["\']?([^"\';\s]+)', re.I)
_CD_FILENAME_STAR_RE = re.compile(r"filename\*\s*=\s*UTF-8''([^\s;]+)", re.I)

_PATH_TRAVERSAL_RE   = re.compile(r'\.\.[\\/]', re.I)
_RTL_OVERRIDE_RE     = re.compile(r'%e2%80%ae|%u202e|‮', re.I)
_DANGEROUS_EXT_RE    = re.compile(
    r'\.(exe|bat|cmd|scr|pif|com|lnk|vbs|js|jse|wsf|wsh|ps1|msi|msp|dll)$',
    re.I
)

_UPLOAD_PATH_RE      = re.compile(
    r'/(?:upload|uploads?|file|files?|media|content|static/[^/]+/|assets?/[^/]+/|storage/)',
    re.I
)


class ContentDispositionSecurityScanner(BaseScanner):
    """Detect Content-Disposition and MIME-type security issues."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "Content-Disposition — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        ct  = resp.headers.get("content-type", "").lower()
        cd  = resp.headers.get("content-disposition", "").lower()
        parsed = urlparse(url)
        path = parsed.path

        self._check_inline_dangerous(url, ct, cd, path)
        self._check_filename_traversal(url, resp.headers.get("content-disposition", ""))
        self._check_dangerous_extension(url, resp.headers.get("content-disposition", ""))

        if not any(r["status"] in ("FAIL", "WARN") for r in self.results):
            log_pass(logger, f"No Content-Disposition issues at {url}")
            self.results.append(self._result(
                url, "Content-Disposition — no inline dangerous MIME issues", "PASS",
                detail=(
                    "Content-Disposition and Content-Type headers are not configured to "
                    "inline dangerous MIME types."
                )
            ))

        return self.results

    def _check_inline_dangerous(self, url: str, ct: str, cd: str, path: str) -> None:
        is_attachment = "attachment" in cd

        if is_attachment:
            return

        if _INLINE_DANGEROUS_CT.search(ct) and _UPLOAD_PATH_RE.search(path):
            log_fail(logger, f"Inline dangerous MIME at {url}: {ct[:60]}")
            self.results.append(self._result(
                url,
                f"Content-Disposition — inline dangerous MIME on upload path: {ct.split(';')[0].strip()}",
                "FAIL",
                detail=(
                    f"The upload/media path '{path}' serves Content-Type: {ct.split(';')[0].strip()} "
                    "without Content-Disposition: attachment. The browser will render this inline, "
                    "and for HTML or SVG content, this enables script execution in the site's origin "
                    "(stored XSS via file upload). "
                    "Fix: add Content-Disposition: attachment to all responses from upload/media paths."
                )
            ))
            return

        if _SCRIPT_CT.search(ct) and _UPLOAD_PATH_RE.search(path):
            log_fail(logger, f"JavaScript served inline on upload path at {url}")
            self.results.append(self._result(
                url,
                "Content-Disposition — JavaScript MIME served from upload path",
                "FAIL",
                detail=(
                    f"Path '{path}' serves Content-Type: {ct.split(';')[0].strip()}, allowing "
                    "JavaScript execution. User-uploaded files served as JavaScript from the "
                    "site's origin execute with full same-origin privileges. "
                    "Fix: never serve user-uploaded files with a JavaScript MIME type; "
                    "add Content-Disposition: attachment."
                )
            ))
            return

        if _INLINE_DANGEROUS_CT.search(ct) and "inline" in cd:
            log_warn(logger, f"Explicit Content-Disposition: inline with scriptable MIME at {url}")
            self.results.append(self._result(
                url,
                f"Content-Disposition — explicit inline with scriptable MIME: {ct.split(';')[0].strip()}",
                "WARN",
                detail=(
                    f"Content-Disposition: inline is set explicitly with Content-Type: "
                    f"{ct.split(';')[0].strip()}. If this path can serve user-supplied "
                    "content, inline rendering enables script execution in this origin. "
                    "Fix: use Content-Disposition: attachment for all file-download paths "
                    "that may serve HTML, SVG, or XML content."
                )
            ))

    def _check_filename_traversal(self, url: str, cd_raw: str) -> None:
        if not cd_raw:
            return

        fn_match = _CD_FILENAME_RE.search(cd_raw)
        fn_star  = _CD_FILENAME_STAR_RE.search(cd_raw)

        filename = (fn_match.group(1) if fn_match else "") or (fn_star.group(1) if fn_star else "")

        if _PATH_TRAVERSAL_RE.search(filename):
            log_fail(logger, f"Path traversal in Content-Disposition filename at {url}")
            self.results.append(self._result(
                url,
                f"Content-Disposition — path traversal in filename: {filename[:80]}",
                "FAIL",
                detail=(
                    f"Content-Disposition header contains filename with path traversal: '{filename}'. "
                    "While modern browsers sanitize this, downstream parsers (wget, curl, "
                    "API clients) may not. Fix: validate and sanitize the filename parameter "
                    "to contain only the base filename without path separators."
                )
            ))

        if _RTL_OVERRIDE_RE.search(filename):
            log_warn(logger, f"RTL override in Content-Disposition filename at {url}")
            self.results.append(self._result(
                url,
                "Content-Disposition — RTL Unicode override in filename",
                "WARN",
                detail=(
                    "Content-Disposition filename contains a right-to-left override character "
                    "(U+202E or encoded equivalent). This can trick users into seeing a "
                    "reversed filename (e.g., 'exe.gpj' displayed as 'jpg.exe'). "
                    "Fix: strip all Unicode control characters from Content-Disposition filenames."
                )
            ))

    def _check_dangerous_extension(self, url: str, cd_raw: str) -> None:
        if not cd_raw or "attachment" not in cd_raw.lower():
            return

        fn_match = _CD_FILENAME_RE.search(cd_raw)
        if not fn_match:
            return

        filename = fn_match.group(1)
        if _DANGEROUS_EXT_RE.search(filename):
            log_warn(logger, f"Dangerous extension in Content-Disposition at {url}: {filename}")
            self.results.append(self._result(
                url,
                f"Content-Disposition — dangerous file extension in attachment: {filename}",
                "WARN",
                detail=(
                    f"Content-Disposition: attachment; filename='{filename}' provides a "
                    "directly executable file. Serving .exe, .bat, .ps1, or similar "
                    "files from a trusted domain may bypass OS-level download warnings. "
                    "Fix: audit whether serving executable file types is necessary; "
                    "consider adding a warning page before the download."
                )
            ))
