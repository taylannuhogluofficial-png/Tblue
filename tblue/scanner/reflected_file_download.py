"""
Reflected File Download (RFD) Scanner.

Reflected File Download (RFD) is an attack that tricks users into downloading
a file from a trusted domain that appears legitimate but contains attacker-
controlled content. Unlike XSS, no script injection occurs — the downloaded
file is a legitimate Windows .bat, .cmd, .sh, or other executable format.

Attack scenario:
  1. Attacker crafts URL: https://trusted.com/api/callback?name=evil.bat%0A%0A@echo+off%0Acmd.exe
  2. Server reflects the `name` parameter in the response body
  3. Attacker sends victim: https://trusted.com/api/callback?name=evil.bat
  4. With `Content-Disposition: attachment; filename=evil.bat`, browser saves it
  5. User opens the .bat file from the Downloads folder — it executes

Key conditions for RFD:
1. Server reflects user input in the response body
2. Response has `Content-Disposition: attachment` with a user-controlled filename
3. Response Content-Type is a common downloadable type (JSON, text, binary)
4. The reflected content starts with a valid script/command prefix

Detection approach (passive):
1. Find endpoints that return Content-Disposition: attachment
2. Check if the filename in Content-Disposition comes from user-controlled input
3. Check if response body reflects URL parameters without encoding
4. Check for endpoints returning JSON/text with user-controlled content + attachment header
5. Detect user-controlled content before Content-Disposition (download triggers)
6. Check for JSONP-style callback reflection with attachment header

Professional equivalent: PortSwigger Research "Reflected File Download",
Detectify "Reflected File Download" scanner.

CWE-494: Download of Code Without Integrity Check
CWE-79: Improper Neutralization (for reflected content path)
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Content-Disposition header patterns
_ATTACHMENT_RE = re.compile(r"attachment", re.I)
_CONTENT_DISP_FILENAME_RE = re.compile(
    r'filename\s*=\s*["\']?([^"\';\s\r\n]+)',
    re.I,
)

# Probe value we inject into parameters to check reflection
_RFD_PROBE = "rfd_tblue_test"
_RFD_EXECUTABLE_EXT = ".bat"

# Dangerous download file extensions that could be executable
_EXEC_EXTENSIONS_RE = re.compile(
    r'\.(bat|cmd|sh|ps1|vbs|js|jse|wsf|wsh|msi|exe|dll|scr|hta|jar|py|rb|pl)$',
    re.I,
)

# Patterns suggesting reflected user input in JSON responses
_CALLBACK_PARAM_RE = re.compile(r'(?:callback|cb|fn|function|jsonp|handler)', re.I)

# Response types that are commonly used for file downloads
_DOWNLOAD_CONTENT_TYPES_RE = re.compile(
    r'application/(?:json|javascript|x-download|octet-stream|zip|pdf)|'
    r'text/(?:plain|javascript|csv|html)',
    re.I,
)

# Script-like prefixes that make a file executable when downloaded
_SCRIPT_PREFIX_RE = re.compile(
    r'^(?:@echo\s+off|::|\$\s*\{|#!/|<\?php|#!|import\s+os|eval\s*\(|'
    r'begin\s+|Set-ExecutionPolicy|python\s+-c|bash\s+-c)',
    re.I | re.M,
)


class ReflectedFileDownloadScanner(BaseScanner):
    """Detect Reflected File Download (RFD) vulnerabilities."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "RFD — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        body = resp.text or ""
        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        found_any = False

        # ── 1. Check if this URL already has attachment header ────────────────
        found_any |= self._check_attachment_response(url, headers, body, parsed)

        # ── 2. Find download/export endpoints in the page ─────────────────────
        found_any |= self._check_linked_downloads(url, base, body)

        # ── 3. Test existing URL parameters for reflection ────────────────────
        found_any |= self._probe_url_parameters(url, parsed)

        # ── 4. Probe known API/JSONP patterns ─────────────────────────────────
        found_any |= self._probe_jsonp_callback(url, base, body)

        if not found_any:
            log_pass(logger, f"No RFD vulnerabilities detected on {url}")
            self.results.append(self._result(
                url,
                "RFD — no Reflected File Download vulnerabilities detected",
                "PASS",
                detail=(
                    "No Content-Disposition: attachment responses with user-controlled "
                    "filenames or reflected content were detected. "
                    "Fix: never use user input for Content-Disposition filename values; "
                    "validate and sanitize all reflected content; "
                    "set Content-Type correctly (avoid text/plain for JSON APIs)."
                )
            ))

        return self.results

    def _check_attachment_response(self, url: str, headers: dict,
                                    body: str, parsed) -> bool:
        content_disp = headers.get("content-disposition", "")
        if not _ATTACHMENT_RE.search(content_disp):
            return False

        found = False

        # Check if filename contains user-controlled parameter value
        fn_match = _CONTENT_DISP_FILENAME_RE.search(content_disp)
        filename = fn_match.group(1) if fn_match else ""

        # Check if query param values appear in filename
        qs = parse_qs(parsed.query, keep_blank_values=True)
        for param, values in qs.items():
            for v in values:
                if v and v in filename:
                    if _EXEC_EXTENSIONS_RE.search(filename):
                        log_fail(logger, f"RFD: user-controlled executable filename in Content-Disposition: {url}")
                        self.results.append(self._result(
                            url,
                            f"RFD — user-controlled executable filename in Content-Disposition (param: {param})",
                            "FAIL",
                            detail=(
                                f"The Content-Disposition header at {url} includes a filename "
                                f"controlled by the '{param}' parameter: '{filename}'. "
                                "This enables RFD — an attacker can set the filename to "
                                "`evil.bat` and the downloaded file will be opened as a "
                                "batch script. "
                                "Fix: never use user-controlled values for the filename "
                                "in Content-Disposition; use a server-side fixed filename."
                            )
                        ))
                        found = True
                    else:
                        log_warn(logger, f"RFD: user-controlled filename in Content-Disposition: {url}")
                        self.results.append(self._result(
                            url,
                            f"RFD — user-controlled filename in Content-Disposition (param: {param})",
                            "WARN",
                            detail=(
                                f"The Content-Disposition filename at {url} is controlled by "
                                f"the '{param}' query parameter: '{filename}'. "
                                "Attackers can manipulate the filename to appear as an executable "
                                "(.bat, .cmd, .sh, .ps1) triggering RFD when combined with "
                                "reflected content in the body. "
                                "Fix: generate filenames server-side; never echo user input "
                                "into Content-Disposition headers."
                            )
                        ))
                        found = True

        # Check for executable extension in any filename
        if filename and _EXEC_EXTENSIONS_RE.search(filename):
            if not found:
                log_warn(logger, f"RFD: executable extension in Content-Disposition filename: {url}")
                self.results.append(self._result(
                    url,
                    f"RFD — executable file extension in Content-Disposition filename: {filename}",
                    "WARN",
                    detail=(
                        f"The Content-Disposition header specifies an executable filename "
                        f"'{filename}'. If the response body also contains user-controlled "
                        "or script-like content, this enables Reflected File Download. "
                        "Fix: restrict download filenames to safe extensions; "
                        "set Content-Type to application/octet-stream for downloads."
                    )
                ))
                found = True

        # Check for script-like content in the response body
        if _SCRIPT_PREFIX_RE.search(body[:200]):
            log_warn(logger, f"RFD: script-like content at start of attachment response: {url}")
            self.results.append(self._result(
                url,
                "RFD — script-like content prefix in downloadable response body",
                "WARN",
                detail=(
                    "The downloadable response starts with a script-like prefix "
                    "(e.g., @echo off, #!/bin/bash, import os). "
                    "If combined with a user-controlled filename, this creates an RFD vector. "
                    "Fix: validate that downloadable content is expected file format data; "
                    "avoid echoing user input at the start of attachment responses."
                )
            ))
            found = True

        return found

    def _check_linked_downloads(self, url: str, base: str, body: str) -> bool:
        """Find download links on the page and probe each."""
        found = False
        try:
            soup = BeautifulSoup(body, "html.parser")
            for tag in soup.find_all(["a", "button", "form"], limit=20):
                href = tag.get("href") or tag.get("action") or ""
                if not href or href.startswith(("#", "mailto:", "javascript:")):
                    continue
                if "download" not in href.lower() and tag.get("download") is None:
                    if not any(ext in href.lower() for ext in
                               (".csv", ".xlsx", ".pdf", ".zip", ".json", "export", "report")):
                        continue
                download_url = urljoin(base, href) if not href.startswith("http") else href
                try:
                    r = self.http.get(download_url)
                    if r is None:
                        continue
                    r_headers = {k.lower(): v for k, v in (r.headers or {}).items()}
                    r_parsed = urlparse(download_url)
                    if self._check_attachment_response(download_url, r_headers,
                                                        r.text or "", r_parsed):
                        found = True
                        break
                except Exception:
                    continue
        except Exception:
            pass
        return found

    def _probe_url_parameters(self, url: str, parsed) -> bool:
        """Probe existing URL parameters by injecting a test value and checking reflection."""
        qs = parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            return False

        for param in list(qs.keys())[:3]:
            probe_params = dict(qs)
            probe_params[param] = [_RFD_PROBE + _RFD_EXECUTABLE_EXT]
            probe_url = parsed._replace(
                query=urlencode({k: v[0] for k, v in probe_params.items()})
            ).geturl()
            try:
                r = self.http.get(probe_url)
                if r is None:
                    continue
                r_headers = {k.lower(): v for k, v in (r.headers or {}).items()}
                content_disp = r_headers.get("content-disposition", "")
                if _ATTACHMENT_RE.search(content_disp):
                    if _RFD_PROBE in content_disp:
                        fn_m = _CONTENT_DISP_FILENAME_RE.search(content_disp)
                        filename = fn_m.group(1) if fn_m else ""
                        if _EXEC_EXTENSIONS_RE.search(filename):
                            log_fail(logger, f"RFD confirmed: probe reflected in executable filename: {probe_url}")
                            self.results.append(self._result(
                                probe_url,
                                f"RFD — probe value reflected as executable filename (param: {param})",
                                "FAIL",
                                detail=(
                                    f"Injecting a test value into parameter '{param}' caused it to "
                                    f"appear as the Content-Disposition filename: '{filename}'. "
                                    "This confirms a Reflected File Download vulnerability. "
                                    "An attacker can set this parameter to 'evil.bat' and craft "
                                    "a URL that tricks users into downloading an executable "
                                    "that appears to come from your trusted domain. "
                                    "Fix: generate filenames server-side and never use URL parameters "
                                    "in Content-Disposition headers."
                                )
                            ))
                            return True
            except Exception:
                continue
        return False

    def _probe_jsonp_callback(self, url: str, base: str, body: str) -> bool:
        """Check JSONP-style endpoints that might reflect user input with attachment header."""
        # Find API endpoints from the page that look like JSONP
        try:
            soup = BeautifulSoup(body, "html.parser")
            for tag in soup.find_all("script", src=True, limit=10):
                src = tag.get("src", "")
                if not src:
                    continue
                src_parsed = urlparse(src if src.startswith("http") else urljoin(base, src))
                qs = parse_qs(src_parsed.query)
                for param in qs:
                    if _CALLBACK_PARAM_RE.search(param):
                        # This is a JSONP endpoint — probe it for RFD
                        probe_params = dict(qs)
                        probe_params[param] = [_RFD_PROBE]
                        probe_url = src_parsed._replace(
                            query=urlencode({k: v[0] for k, v in probe_params.items()})
                        ).geturl()
                        try:
                            r = self.http.get(probe_url)
                            if r is None:
                                continue
                            r_headers = {k.lower(): v for k, v in (r.headers or {}).items()}
                            r_body = r.text or ""
                            content_disp = r_headers.get("content-disposition", "")
                            if _ATTACHMENT_RE.search(content_disp) and _RFD_PROBE in r_body:
                                log_fail(logger, f"RFD via JSONP: probe reflected in attachment response: {probe_url}")
                                self.results.append(self._result(
                                    probe_url,
                                    f"RFD — JSONP callback reflected in attachment response body (param: {param})",
                                    "FAIL",
                                    detail=(
                                        f"The JSONP endpoint {src} reflects the '{param}' parameter "
                                        "in the response body AND returns Content-Disposition: attachment. "
                                        "This is a Reflected File Download vulnerability: the attacker "
                                        f"sets '{param}' to script content like '@echo off\\ncmd.exe' "
                                        "and the downloaded file becomes an executable batch script "
                                        "that appears to originate from your trusted domain. "
                                        "Fix: disable JSONP; use CORS instead; "
                                        "never return Content-Disposition: attachment on API endpoints."
                                    )
                                ))
                                return True
                        except Exception:
                            continue
        except Exception:
            pass
        return False
