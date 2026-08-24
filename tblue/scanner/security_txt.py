"""
security.txt scanner (RFC 9116).

Checks for the presence and validity of a security.txt file, which allows
security researchers to know how to report vulnerabilities responsibly.

Canonical locations:
  /.well-known/security.txt  (preferred per RFC 9116)
  /security.txt              (legacy fallback)
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse, urljoin

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_PATHS = ["/.well-known/security.txt", "/security.txt"]

_REQUIRED_FIELDS = {
    "Contact":  re.compile(r"^Contact\s*:", re.MULTILINE | re.IGNORECASE),
    "Expires":  re.compile(r"^Expires\s*:", re.MULTILINE | re.IGNORECASE),
}

_RECOMMENDED_FIELDS = {
    "Policy":         re.compile(r"^Policy\s*:", re.MULTILINE | re.IGNORECASE),
    "Encryption":     re.compile(r"^Encryption\s*:", re.MULTILINE | re.IGNORECASE),
    "Acknowledgments": re.compile(r"^Acknowledgments?\s*:", re.MULTILINE | re.IGNORECASE),
}


class SecurityTxtScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        found_url, body = self._find(base)

        if found_url is None:
            log_warn(logger, f"security.txt not found — {url}")
            self.results.append(self._result(
                url, "security.txt — missing", "WARN",
                detail=(
                    "No security.txt file found at /.well-known/security.txt or /security.txt. "
                    "RFC 9116 defines this file as the standard way to tell security researchers "
                    "how to contact you when they find a vulnerability. Without it, researchers "
                    "may not report issues — or may publish them directly. "
                    "Fix: create /.well-known/security.txt with at least Contact and Expires fields. "
                    "Use https://securitytxt.org to generate one."
                )
            ))
            return self.results

        # File exists — validate required fields
        missing_required = [f for f, rx in _REQUIRED_FIELDS.items() if not rx.search(body)]
        missing_recommended = [f for f, rx in _RECOMMENDED_FIELDS.items() if not rx.search(body)]

        if missing_required:
            log_warn(logger, f"security.txt found but missing required fields: {missing_required}")
            self.results.append(self._result(
                found_url, "security.txt — incomplete (missing required fields)", "WARN",
                detail=(
                    f"security.txt found at {found_url} but is missing required RFC 9116 fields: "
                    f"{', '.join(missing_required)}. "
                    "Contact tells researchers where to send reports; "
                    "Expires tells them when the file becomes stale. "
                    "Fix: add the missing fields. Example:\n"
                    "  Contact: mailto:security@yourdomain.com\n"
                    "  Expires: 2026-12-31T23:59:59.000Z"
                )
            ))
        elif missing_recommended:
            log_pass(logger, f"security.txt valid — {found_url} (missing optional: {missing_recommended})")
            self.results.append(self._result(
                found_url, "security.txt — present and valid", "PASS",
                detail=(
                    f"security.txt found at {found_url} with all required fields. "
                    f"Optional fields not present: {', '.join(missing_recommended)}."
                )
            ))
        else:
            log_pass(logger, f"security.txt valid and complete — {found_url}")
            self.results.append(self._result(
                found_url, "security.txt — present and valid", "PASS",
                detail=f"security.txt found at {found_url} with all required and recommended fields."
            ))

        return self.results

    def _find(self, base: str):
        for path in _PATHS:
            url = urljoin(base, path)
            resp = self.http.get(url, allow_redirects=True)
            if resp and resp.status_code == 200:
                ct = resp.headers.get("content-type", "")
                body = resp.text or ""
                # Avoid false positives from HTML 200s (custom 404 pages)
                if "<html" in body[:200].lower() and "text/plain" not in ct:
                    continue
                if "Contact" in body or "contact" in body:
                    return url, body
        return None, None
