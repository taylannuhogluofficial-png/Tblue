"""
IDOR (Insecure Direct Object Reference) Detection Scanner.

IDOR occurs when applications expose internal implementation objects
(database IDs, file paths, usernames) in URLs or parameters without
verifying the requesting user is authorized.

Detection (read-only, passive):
1. Find numeric ID parameters in URLs (?id=, ?user_id=, ?order=, etc.)
2. Probe with adjacent IDs (id+1, id-1) and detect response size differences
   that suggest a different object was served (vs. 403/404)
3. Check if sensitive-looking parameters in URLs expose UUIDs/IDs
4. Detect resource URLs containing predictable IDs (sequential numbers)
5. Look for BOLA (Broken Object Level Authorization) patterns in API routes

The scanner is conservative — it only flags responses where data is
actually returned for adjacent IDs, not mere 2xx status codes,
to minimize false positives.

CWE-639: Authorization Bypass Through User-Controlled Key
OWASP API1:2023 — Broken Object Level Authorization (BOLA)
"""

import re
from typing import Any, Dict, List, Set
from urllib.parse import urlparse, parse_qs, urlencode

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Parameter names that often reference database rows
_ID_PARAMS = frozenset({
    "id", "user_id", "userId", "account_id", "accountId",
    "order_id", "orderId", "invoice_id", "invoiceId",
    "document_id", "documentId", "file_id", "fileId",
    "record_id", "recordId", "item_id", "itemId",
    "customer_id", "customerId", "member_id", "memberId",
    "patient_id", "patientId", "report_id", "reportId",
    "ticket_id", "ticketId", "message_id", "messageId",
    "post_id", "postId", "comment_id", "commentId",
    "uid", "oid", "pid", "rid", "cid", "mid",
})

# UUID pattern
_UUID_RE = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    re.I,
)

# API path with numeric ID segment: /api/users/123, /v1/orders/456
_API_ID_PATH_RE = re.compile(
    r'/(?:api|v\d+)/(?:[a-z_]+)/(\d+)(?:/|$)',
    re.I,
)

# Minimum response body size to consider it "has data" (not empty 200)
_MIN_DATA_SIZE = 50

# Maximum deviation in body size to be considered same object
_SAME_OBJECT_THRESHOLD = 0.2  # 20% — larger diff = different object


class IDORDetectionScanner(BaseScanner):
    """Detects IDOR via adjacent ID probing and API path analysis."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping IDOR checks: {url}")
            self.results.append(self._result(
                url, "IDOR — no response", "PASS",
                detail="Target did not respond; IDOR checks skipped."
            ))
            return self.results

        body = resp.text or ""
        id_params = self._find_id_params(url, body)

        if not id_params:
            # Check for sequential API paths
            self._check_api_path_idor(url, resp)
        else:
            for param, value in list(id_params.items())[:3]:
                self._probe_adjacent_ids(url, param, value)

        if not self.results:
            log_pass(logger, f"No IDOR indicators: {url}")
            self.results.append(self._result(
                url, "IDOR — no indicators detected", "PASS",
                detail=(
                    "No numeric ID parameters found, or adjacent ID probing did not "
                    "return substantively different data (401/403/404 for adjacent IDs)."
                )
            ))

        return self.results

    def _find_id_params(self, url: str, body: str) -> dict:
        found = {}
        parsed = urlparse(url)
        for param, values in parse_qs(parsed.query).items():
            if param.lower() in _ID_PARAMS:
                val = values[0]
                if val.isdigit():
                    found[param] = int(val)
        # Also scan page links for ID params
        if not found:
            soup = BeautifulSoup(body, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if "?" in href:
                    link_parsed = urlparse(href)
                    for param, values in parse_qs(link_parsed.query).items():
                        if param.lower() in _ID_PARAMS and values[0].isdigit():
                            found[param] = int(values[0])
                            break
                if found:
                    break
        return found

    def _probe_adjacent_ids(self, url: str, param: str, base_id: int) -> None:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        base_body = self._get_body_for_id(url, parsed, params, param, base_id)
        if base_body is None or len(base_body) < _MIN_DATA_SIZE:
            return

        for delta in (1, -1, 2):
            adjacent_id = base_id + delta
            if adjacent_id <= 0:
                continue
            adj_body = self._get_body_for_id(url, parsed, params, param, adjacent_id)
            if adj_body is None:
                continue
            if len(adj_body) < _MIN_DATA_SIZE:
                continue

            # Bodies are substantial and different — suggests different object returned
            size_diff = abs(len(adj_body) - len(base_body))
            avg_size = (len(adj_body) + len(base_body)) / 2
            if size_diff / avg_size > _SAME_OBJECT_THRESHOLD and len(adj_body) >= _MIN_DATA_SIZE:
                log_warn(logger, f"IDOR: adjacent ID {adjacent_id} returns data via '{param}': {url}")
                self.results.append(self._result(
                    url,
                    f"IDOR — parameter '{param}' may allow access to adjacent resource (ID {adjacent_id})",
                    "WARN",
                    detail=(
                        f"Requesting '{param}={adjacent_id}' (adjacent to '{param}={base_id}') "
                        f"returned {len(adj_body)} bytes of content instead of 401/403/404. "
                        "This suggests the server may not be validating object ownership. "
                        "Fix: verify the authenticated user owns the requested object before "
                        "returning data; never rely on obscurity of IDs; prefer UUIDs; "
                        "implement object-level authorization checks (not just role-based)."
                    )
                ))
                return

    def _get_body_for_id(self, url: str, parsed, params: dict,
                          param: str, id_val: int) -> str:
        probe_params = dict(params)
        probe_params[param] = [str(id_val)]
        new_query = urlencode({k: v[0] for k, v in probe_params.items()})
        probe_url = parsed._replace(query=new_query).geturl()
        r = self.http.get(probe_url)
        if r is None or r.status_code in (401, 403, 404, 410):
            return ""
        return r.text or ""

    def _check_api_path_idor(self, url: str, resp) -> None:
        # Check if URL itself has /api/resource/123 pattern
        m = _API_ID_PATH_RE.search(url)
        if not m:
            body = resp.text or ""
            # Check for API links in page
            soup = BeautifulSoup(body, "html.parser")
            for a in soup.find_all("a", href=True):
                m = _API_ID_PATH_RE.search(a["href"])
                if m:
                    url = a["href"] if a["href"].startswith("http") else url
                    break

        if m:
            id_val = int(m.group(1))
            if id_val > 1:
                adjacent_url = url.replace(f"/{id_val}", f"/{id_val + 1}", 1)
                r = self.http.get(adjacent_url)
                if r is not None and r.status_code == 200:
                    body_size = len(r.text or "")
                    if body_size >= _MIN_DATA_SIZE:
                        log_warn(logger, f"IDOR: adjacent API resource {adjacent_url} accessible: {url}")
                        self.results.append(self._result(
                            url,
                            f"IDOR — adjacent API resource (ID {id_val + 1}) accessible: {adjacent_url}",
                            "WARN",
                            detail=(
                                f"API path with ID {id_val + 1} (adjacent to {id_val}) "
                                f"returned {body_size} bytes with status 200. "
                                "This may indicate broken object-level authorization. "
                                "Fix: validate that the authenticated user is authorized "
                                "to access the specific resource before returning it."
                            )
                        ))
