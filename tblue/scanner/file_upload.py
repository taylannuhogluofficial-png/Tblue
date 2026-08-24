"""
File Upload Security Scanner.

Detects file upload endpoints and checks for dangerous configurations:

1. File input fields in forms (<input type="file">)
2. Multipart/form-data POST endpoints
3. Missing or overly permissive accept attributes (accept="*/*" or absent)
4. Upload path disclosure in responses (full server path to uploaded file)
5. Dangerous accepted MIME types (executable: .exe, .php, .jsp, .sh, .py)
6. Missing CSRF protection on upload forms
7. Content-Disposition headers revealing upload directory structure
8. PUT method enabled (which may allow direct file upload)

Unrestricted file upload (OWASP A04 / CWE-434) is a critical vulnerability
enabling webshell deployment and RCE.

All checks are passive analysis — no files are uploaded.
"""

import re
from typing import Any, Dict, List, Set
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# MIME types / extensions that are dangerous if uploadable
_DANGEROUS_ACCEPT: Set[str] = {
    ".php", ".php3", ".php4", ".php5", ".phtml",
    ".asp", ".aspx", ".ashx", ".asmx",
    ".jsp", ".jspx",
    ".sh", ".bash", ".zsh", ".ksh",
    ".py", ".rb", ".pl", ".cgi",
    ".exe", ".bat", ".cmd", ".com", ".vbs", ".ps1",
    ".htaccess", ".htpasswd",
    "text/html", "application/x-httpd-php",
    "application/x-httpd-asp",
    "application/octet-stream",
}

# Upload path disclosure patterns in response bodies
_UPLOAD_PATH_RE = re.compile(
    r"""(?:uploaded?\s+(?:to|at|path|file)|saved\s+(?:to|as|at)|
    file(?:path|_path|name|_name)\s*[=:]\s*|
    /uploads?/|/files?/|/media/|/static/uploads?/|
    /tmp/|/var/www/|/home/www/|wwwroot/|htdocs/)
    ([^\s"'<>\n]{4,100})""",
    re.I | re.X,
)

# Server-side file path disclosure in Content-Disposition
_CONTENT_DISP_PATH_RE = re.compile(
    r"filename\s*=\s*[\"']?([A-Za-z]:[\\\/]|\/(?:var|home|tmp|srv|www|uploads?)[\/\\])",
    re.I,
)

# CSRF token absence check — look for csrf/token in form
_CSRF_TOKEN_RE = re.compile(
    r"csrf|_token|authenticity_token|__RequestVerificationToken",
    re.I,
)


class FileUploadScanner(BaseScanner):
    """Detect file upload endpoints and assess their security configuration."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if not resp:
            return self.results

        body = resp.text or ""
        soup = BeautifulSoup(body, "html.parser")

        found_upload = False

        # ── Scan all forms for file inputs ────────────────────────────────────
        for form in soup.find_all("form"):
            file_inputs = form.find_all("input", {"type": "file"})
            if not file_inputs:
                continue

            found_upload = True
            form_action = form.attrs.get("action", url)
            if not form_action.startswith("http"):
                form_action = urljoin(url, form_action)
            form_method = form.attrs.get("method", "get").upper()
            enctype = form.attrs.get("enctype", "")
            form_html = str(form)[:300]

            # Check for CSRF token
            has_csrf = bool(_CSRF_TOKEN_RE.search(form_html))

            for file_input in file_inputs:
                input_name = file_input.attrs.get("name", "unnamed")
                accept = file_input.attrs.get("accept", "")
                accept_lower = accept.lower()

                # ── Missing accept attribute ──────────────────────────────────
                if not accept:
                    log_warn(logger, f"File upload input '{input_name}' has no accept attribute")
                    self.results.append(self._result(
                        form_action,
                        f"File upload — no content-type restriction (input: {input_name})",
                        "WARN",
                        detail=(
                            f"File upload input '{input_name}' on form at {form_action} "
                            "has no 'accept' attribute, meaning any file type can be selected. "
                            "While client-side 'accept' is bypassable, its absence indicates "
                            "no intended type restriction. "
                            "Fix: add 'accept' attribute with allowed MIME types; "
                            "critically, validate file type server-side using magic bytes, "
                            "not just the filename extension or Content-Type header."
                        )
                    ))

                # ── Dangerous accept types ────────────────────────────────────
                dangerous_found = []
                for dangerous in _DANGEROUS_ACCEPT:
                    if dangerous.lower() in accept_lower:
                        dangerous_found.append(dangerous)

                if dangerous_found:
                    log_fail(logger, f"Dangerous file types accepted: {dangerous_found}")
                    self.results.append(self._result(
                        form_action,
                        f"File upload — dangerous MIME types accepted ({', '.join(dangerous_found)})",
                        "FAIL",
                        detail=(
                            f"Upload input '{input_name}' accepts dangerous file types: "
                            f"{', '.join(dangerous_found)}. "
                            "Accepting server-executable file types (PHP, ASP, JSP, Python, shell) "
                            "enables webshell upload and remote code execution. "
                            "Fix: allowlist only safe MIME types (image/jpeg, image/png, "
                            "application/pdf); validate server-side with magic byte inspection; "
                            "store uploads outside the web root; rename files on upload; "
                            "set X-Content-Type-Options: nosniff."
                        )
                    ))

                # ── Wildcard accept ───────────────────────────────────────────
                if accept in ("*/*", "*", ".*"):
                    log_fail(logger, f"File upload accepts all file types: {form_action}")
                    self.results.append(self._result(
                        form_action,
                        "File upload — wildcard accept (*/*) allows any file type",
                        "FAIL",
                        detail=(
                            f"Upload input '{input_name}' uses accept='*/*' — any file type "
                            "is permitted. This is equivalent to no restriction. "
                            "Fix: specify exact MIME types; validate server-side."
                        )
                    ))

            # ── Missing CSRF on upload form ───────────────────────────────────
            if form_method == "POST" and not has_csrf:
                log_warn(logger, f"File upload form at {form_action} lacks CSRF token")
                self.results.append(self._result(
                    form_action,
                    "File upload — no CSRF token on upload form",
                    "WARN",
                    detail=(
                        f"The file upload form at {form_action} uses POST but no CSRF "
                        "token was detected. An attacker with a CSRF bypass could "
                        "trick authenticated users into uploading files without consent. "
                        "Fix: include a CSRF token on all state-changing forms."
                    )
                ))

        # ── Upload path disclosure in response ────────────────────────────────
        path_match = _UPLOAD_PATH_RE.search(body)
        if path_match:
            disclosed_path = path_match.group(0)[:120]
            log_warn(logger, f"Upload path disclosed in response: {disclosed_path}")
            self.results.append(self._result(
                url,
                "File upload — server-side upload path disclosed in response",
                "WARN",
                detail=(
                    f"Server-side upload path found in response: '{disclosed_path}'. "
                    "Disclosed upload paths reveal server directory structure and allow "
                    "attackers to directly access uploaded files. "
                    "Fix: return only relative or obfuscated paths; use content-addressed "
                    "storage (random UUID filenames); verify uploaded files are served "
                    "from a separate origin or CDN without script execution."
                )
            ))

        # ── Content-Disposition with server path ──────────────────────────────
        content_disp = resp.headers.get("content-disposition", "")
        if _CONTENT_DISP_PATH_RE.search(content_disp):
            log_warn(logger, f"Server path in Content-Disposition: {content_disp}")
            self.results.append(self._result(
                url,
                "File upload — server file path in Content-Disposition header",
                "WARN",
                detail=(
                    f"Content-Disposition header reveals a server-side path: '{content_disp}'. "
                    "Fix: use only filenames (not full paths) in Content-Disposition headers."
                )
            ))

        # ── PUT method check ──────────────────────────────────────────────────
        try:
            options_resp = self.http.get(url)
            if options_resp:
                allow_header = options_resp.headers.get("allow", "")
                if "PUT" in allow_header.upper():
                    log_warn(logger, f"PUT method allowed — potential direct upload at {url}")
                    self.results.append(self._result(
                        url,
                        "File upload — HTTP PUT method enabled",
                        "WARN",
                        detail=(
                            f"HTTP PUT is listed in the Allow header: {allow_header}. "
                            "If PUT is permitted on web-accessible paths, attackers may "
                            "be able to upload arbitrary files directly. "
                            "Fix: disable PUT on all paths unless explicitly required; "
                            "enforce authentication and path validation on PUT handlers."
                        )
                    ))
        except Exception:
            pass

        if not found_upload and not self.results:
            log_pass(logger, f"No file upload endpoints detected on {url}")
            self.results.append(self._result(
                url, "File upload — no upload forms detected", "PASS",
                detail="No <input type='file'> forms found on this page."
            ))

        return self.results
