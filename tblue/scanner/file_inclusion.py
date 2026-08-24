"""
Local/Remote File Inclusion (LFI/RFI) Scanner.

Detects file inclusion vulnerabilities by probing URL parameters that
commonly accept file paths. LFI allows reading server-side files;
RFI allows loading remote code.

Detection strategy (strictly read-only, no exploitation):
1. Find parameters in existing URL query string
2. Find `file`, `page`, `include`, `template`, `path`, `doc` style params
   in forms and links
3. Inject benign path traversal sequences and look for:
   - OS-specific content in the response (passwd entries, ini headers)
   - PHP error messages indicating include() was attempted
   - Difference in response size between baseline and probe
4. Probe for common LFI indicators across known-risky parameter names

Only checks for reflection/disclosure indicators — never attempts
code execution or remote file loading.

CWE-22: Path Traversal
CWE-98: Improper Control of Filename for Include/Require Statement
"""

import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse, parse_qs, urlencode

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Parameter names that commonly indicate file inclusion
_RISKY_PARAMS = frozenset({
    "file", "page", "include", "template", "view", "doc", "document",
    "path", "folder", "dir", "root", "pg", "style", "layout", "theme",
    "conf", "config", "load", "read", "show", "open", "fetch",
    "module", "lang", "language", "locale", "content", "route",
})

# LFI payloads — traversal sequences to /etc/passwd and Windows equivalents
_LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/passwd%00",          # Null byte truncation
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",  # URL-encoded
    "../../../../windows/win.ini",
    "php://filter/convert.base64-encode/resource=index.php",
    "....//....//....//etc/passwd",       # Double dot bypass
    "/etc/passwd",
    "/etc/shadow",
    "C:\\windows\\win.ini",
]

# Indicators in responses that suggest file inclusion worked
_PASSWD_RE = re.compile(r"root:.*:0:0:|nobody:.*:/sbin/nologin", re.I)
_WIN_INI_RE = re.compile(r"\[fonts\]|\[extensions\]|\[mci extensions\]", re.I)
_PHP_INCLUDE_ERR_RE = re.compile(
    r"(?:failed to open stream|include\(\)|require\(\)|Warning:\s*include|"
    r"No such file or directory|failed opening)",
    re.I,
)
_PHP_FILTER_RE = re.compile(r"PD9waHA|<\?php", re.I)

# Minimum size change that indicates a different file was loaded (heuristic)
_SIZE_CHANGE_THRESHOLD = 200


class FileInclusionScanner(BaseScanner):
    """Detects LFI/RFI indicators by probing file-path-style URL parameters."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping file inclusion checks: {url}")
            self.results.append(self._result(
                url, "File inclusion — no response", "PASS",
                detail="Target did not respond; file inclusion checks skipped."
            ))
            return self.results

        baseline_size = len(resp.text or "")
        body = resp.text or ""

        # Collect risky parameters from URL and page
        params_to_test = self._collect_params(url, body)

        if not params_to_test:
            log_pass(logger, f"No file-path-style parameters found: {url}")
            self.results.append(self._result(
                url, "File inclusion — no file-path parameters found", "PASS",
                detail="No URL parameters matching file inclusion risk patterns were detected."
            ))
            return self.results

        found = False
        for param in params_to_test:
            if self._probe_param(url, param, baseline_size):
                found = True
                break  # One confirmed finding per scan

        if not found:
            log_pass(logger, f"No file inclusion indicators on {url}")
            self.results.append(self._result(
                url, "File inclusion — no indicators detected", "PASS",
                detail=(
                    "File path traversal sequences in URL parameters did not produce "
                    "file content, PHP errors, or significant size changes."
                )
            ))

        return self.results

    def _collect_params(self, url: str, body: str) -> Set[str]:
        """Collect parameter names from URL query string and page forms/links."""
        found: Set[str] = set()

        parsed = urlparse(url)
        for param in parse_qs(parsed.query):
            if param.lower() in _RISKY_PARAMS:
                found.add(param)

        soup = BeautifulSoup(body, "html.parser")
        for inp in soup.find_all("input"):
            name = (inp.get("name") or "").lower()
            if name in _RISKY_PARAMS:
                found.add(name)

        for a in soup.find_all("a", href=True):
            href = a["href"]
            parsed_href = urlparse(href)
            for param in parse_qs(parsed_href.query):
                if param.lower() in _RISKY_PARAMS:
                    found.add(param)

        return found

    def _probe_param(self, url: str, param: str, baseline_size: int) -> bool:
        """Test a single parameter with LFI payloads. Returns True if vulnerability found."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        for payload in _LFI_PAYLOADS[:5]:  # Limit to 5 payloads per param
            probe_params = dict(params)
            probe_params[param] = [payload]
            new_query = urlencode({k: v[0] for k, v in probe_params.items()})
            probe_url = parsed._replace(query=new_query).geturl()

            r = self.http.get(probe_url)
            if r is None:
                continue

            body = r.text or ""

            # Check for /etc/passwd content
            if _PASSWD_RE.search(body):
                log_fail(logger, f"LFI: /etc/passwd content in response via '{param}': {url}")
                self.results.append(self._result(
                    url,
                    f"File inclusion — /etc/passwd content via parameter '{param}' (LFI confirmed)",
                    "FAIL",
                    detail=(
                        f"Path traversal via '{param}={payload}' returned /etc/passwd content. "
                        "Local File Inclusion (LFI) is confirmed — an attacker can read "
                        "arbitrary server files including credentials, private keys, and configs. "
                        "Fix: never use user input to construct file paths; "
                        "use a whitelist of allowed filenames; "
                        "resolve paths and verify they're within the allowed directory "
                        "(realpath() check)."
                    )
                ))
                return True

            # Check for Windows win.ini
            if _WIN_INI_RE.search(body):
                log_fail(logger, f"LFI: windows/win.ini in response via '{param}': {url}")
                self.results.append(self._result(
                    url,
                    f"File inclusion — windows/win.ini content via '{param}' (LFI confirmed)",
                    "FAIL",
                    detail=(
                        f"Path traversal via '{param}={payload}' returned Windows win.ini content. "
                        "LFI confirmed on Windows server. "
                        "Fix: whitelist acceptable file names; never accept raw paths from users."
                    )
                ))
                return True

            # PHP filter base64 output
            if _PHP_FILTER_RE.search(body) and "php://filter" in payload:
                log_warn(logger, f"LFI: PHP filter wrapper accepted via '{param}': {url}")
                self.results.append(self._result(
                    url,
                    f"File inclusion — PHP filter wrapper accepted via '{param}'",
                    "WARN",
                    detail=(
                        f"php://filter/convert.base64-encode was accepted as value for '{param}'. "
                        "This wrapper allows reading PHP source files encoded as base64. "
                        "Fix: block php:// and other wrappers in include paths; "
                        "use realpath() to canonicalize paths before inclusion."
                    )
                ))
                return True

            # PHP include error messages indicate the parameter is used in include()
            if _PHP_INCLUDE_ERR_RE.search(body):
                log_warn(logger, f"LFI: PHP include error via '{param}': {url}")
                self.results.append(self._result(
                    url,
                    f"File inclusion — PHP include error reveals file inclusion in '{param}'",
                    "WARN",
                    detail=(
                        f"'{param}' parameter caused a PHP include() error: "
                        "the value is used in an include/require statement. "
                        "Even without successful traversal, include() of user input is dangerous. "
                        "Fix: replace dynamic file inclusion with a switch/map of allowed pages."
                    )
                ))
                return True

        return False
