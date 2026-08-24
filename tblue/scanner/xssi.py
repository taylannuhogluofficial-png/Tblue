"""
Cross-Site Script Inclusion (XSSI) Scanner.

XSSI exploits the fact that <script src="..."> can load cross-origin URLs and,
in some browser/JavaScript engine combinations, extract data from responses that
are either:

  1. JSON arrays ([...]) — older browsers exposed Array constructor callbacks,
     modern XSSI uses prototype property shadowing or MutationObserver tricks.
  2. JavaScript-like responses — if Content-Type lacks nosniff, browsers may
     execute application/json as text/javascript, turning data into JS.
  3. JSONP with unvalidated callbacks — function wrapping makes data executable
     in any browser; examined briefly here (full JSONP analysis in json_injection.py).

Modern XSSI mitigations:
  a) Anti-XSSI prefix: )]}'\n, while(1);, for(;;); — causes syntax error when
     executed as script, preventing data extraction.
  b) X-Content-Type-Options: nosniff — prevents MIME-type sniffing.
  c) Correct Content-Type: application/json.
  d) SameSite cookies — limits cross-origin cookie inclusion.

OWASP Testing Guide: WSTG-CLNT-13.
Professional equivalents: Detectify "XSSI", PortSwigger Research,
Mozilla Observatory, Invicti "JSON Hijacking".

CWE-284: Improper Access Control
CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
CWE-829: Inclusion of Functionality from Untrusted Control Sphere
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# --- Anti-XSSI prefix patterns ---

# Responses STARTING with these patterns are safe from basic XSSI
_ANTI_XSSI_PREFIX_RE = re.compile(
    r"""^(?:\)\]\}['\"]?\s*\n|while\s*\(1\)\s*;|for\s*\(;;\)\s*;|/\*.*?\*/|//|throw\s+\d+;)""",
    re.I | re.M,
)

# JSON array at top level (higher XSSI risk)
_JSON_ARRAY_START_RE = re.compile(r'^\s*\[', re.M)

# JSON object at top level (lower risk, but still possible with older techniques)
_JSON_OBJECT_START_RE = re.compile(r'^\s*\{', re.M)

# Content type indicators
_JSON_CONTENT_TYPE_RE = re.compile(
    r'application/json|text/json',
    re.I,
)
_JS_CONTENT_TYPE_RE = re.compile(
    r'text/javascript|application/javascript|application/x-javascript',
    re.I,
)

# Script tags pointing to API endpoints in the page
_API_SCRIPT_SRC_RE = re.compile(
    r'<script[^>]+src\s*=\s*["\']([^"\']+(?:/api/|/json|\.json)[^"\']*)["\']',
    re.I,
)

# API links from the page (JSON-like href patterns)
_API_LINK_RE = re.compile(
    r'(?:href|action|src)\s*=\s*["\']([^"\']*(?:/api/|/json|\.json|/graphql)[^"\']*)["\']',
    re.I,
)

# Sensitive field names that indicate data worth stealing
_SENSITIVE_FIELD_RE = re.compile(
    r'"(?:email|username|user_id|userId|token|auth|role|permission|admin|ssn|'
    r'credit_card|phone|address|salary|balance|account_id)"\s*:',
    re.I,
)

# Common API paths to probe
_API_PATHS = [
    "/api/user",
    "/api/users",
    "/api/me",
    "/api/profile",
    "/api/account",
    "/api/data",
    "/api/config",
    "/api/settings",
    "/user.json",
    "/users.json",
    "/profile.json",
    "/me.json",
    "/data.json",
    "/config.json",
    "/api/v1/user",
    "/api/v1/users",
    "/api/v1/me",
    "/api/v2/user",
    "/rest/user",
    "/rest/users",
]


class XSSIScanner(BaseScanner):
    """Detect Cross-Site Script Inclusion risks via JSON array responses and missing anti-XSSI prefixes."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "XSSI — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        body = resp.text or ""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Collect candidate API URLs from page content
        api_urls: set = set()

        # 1. Find script tags loading JSON data from same origin
        for src in _API_SCRIPT_SRC_RE.findall(body):
            if src.startswith("/"):
                api_urls.add(base + src)
            elif src.startswith(("http://", "https://")):
                if urlparse(src).netloc == parsed.netloc:
                    api_urls.add(src)

        # 2. Find API links in the page
        for href in _API_LINK_RE.findall(body):
            if href.startswith("/"):
                api_urls.add(base + href)
            elif href.startswith(("http://", "https://")):
                if urlparse(href).netloc == parsed.netloc:
                    api_urls.add(href)

        # 3. Check common API paths
        for path in _API_PATHS:
            api_urls.add(base + path)

        # Also check if the main page itself is a JSON response
        self._check_json_response(url, resp.headers, body)

        # Probe API endpoints
        probed = set()
        for api_url in list(api_urls)[:25]:  # Cap at 25 to avoid excessive requests
            if api_url in probed:
                continue
            probed.add(api_url)
            try:
                r = self.http.get(api_url)
                if r is None or r.status_code != 200:
                    continue
                rbody = r.text or ""
                if len(rbody) < 2:
                    continue
                self._check_json_response(api_url, r.headers, rbody)
            except Exception:
                continue

        if not any(r["status"] in ("FAIL", "WARN") for r in self.results):
            log_pass(logger, f"XSSI — no vulnerable JSON endpoints found on {base}")
            self.results.append(self._result(
                url,
                "XSSI — no cross-site script inclusion vulnerabilities found",
                "PASS",
                detail=(
                    "Checked JSON API responses for: anti-XSSI prefixes, correct Content-Type, "
                    "X-Content-Type-Options: nosniff, and JSON array at top level. "
                    "No unprotected JSON array responses found. "
                    "Fix: add anti-XSSI prefix (e.g. ')]}\\'' + '\\n') before all JSON array responses; "
                    "always send Content-Type: application/json and X-Content-Type-Options: nosniff."
                )
            ))

        return self.results

    def _check_json_response(self, url: str, headers: Any, body: str) -> None:
        """Analyze a single HTTP response for XSSI indicators."""
        if not body:
            return

        content_type = str(headers.get("content-type", "") or "").lower()
        nosniff = str(headers.get("x-content-type-options", "") or "").lower()
        cors_origin = str(headers.get("access-control-allow-origin", "") or "")

        is_json_ct = bool(_JSON_CONTENT_TYPE_RE.search(content_type))
        is_js_ct = bool(_JS_CONTENT_TYPE_RE.search(content_type))
        has_nosniff = "nosniff" in nosniff
        is_json_array = bool(_JSON_ARRAY_START_RE.match(body.strip()))
        is_json_object = bool(_JSON_OBJECT_START_RE.match(body.strip()))
        has_anti_xssi = bool(_ANTI_XSSI_PREFIX_RE.match(body.strip()))
        is_cors_open = cors_origin in ("*",) or bool(cors_origin)
        has_sensitive = bool(_SENSITIVE_FIELD_RE.search(body[:2000]))

        # Only analyze likely JSON API responses
        if not (is_json_ct or is_js_ct or is_json_array or is_json_object):
            return

        if not (is_json_array or is_json_object):
            return

        # Case 1: JSON array without anti-XSSI prefix
        if is_json_array and not has_anti_xssi:
            severity = "FAIL" if (is_cors_open or has_sensitive) else "WARN"
            cors_info = f" CORS origin: {cors_origin}." if cors_origin else ""
            sensitive_info = " Sensitive field names detected in response body." if has_sensitive else ""
            log_fail(logger, f"XSSI: JSON array without anti-XSSI prefix at {url}")
            self.results.append(self._result(
                url,
                "XSSI — JSON array response missing anti-XSSI prefix",
                severity,
                detail=(
                    f"The endpoint {url} returns a JSON array ([...]) at the top level "
                    "without an anti-XSSI prefix. "
                    f"{cors_info}{sensitive_info} "
                    "Attackers can include this URL in a <script> tag and use prototype "
                    "property tricks (Object.prototype getter poisoning) to extract array elements. "
                    "Fix: prepend ')]}\\'' + '\\n' (or 'while(1);\\n') to all JSON array responses. "
                    "Also set X-Content-Type-Options: nosniff and Content-Type: application/json. "
                    "CWE-284. OWASP WSTG-CLNT-13."
                ),
            ))
            return  # Don't double-report the same endpoint

        # Case 2: JSON served without nosniff (MIME sniffing risk)
        if (is_json_ct or is_json_object) and not has_nosniff:
            log_warn(logger, f"XSSI: JSON response without nosniff at {url}")
            self.results.append(self._result(
                url,
                "XSSI — JSON response missing X-Content-Type-Options: nosniff",
                "WARN",
                detail=(
                    f"The endpoint {url} returns JSON without 'X-Content-Type-Options: nosniff'. "
                    "Without nosniff, browsers may MIME-sniff the response as JavaScript "
                    "if loaded via <script src>, making the response executable as script. "
                    "Fix: add 'X-Content-Type-Options: nosniff' to all JSON API responses. "
                    "CWE-284."
                ),
            ))

        # Case 3: JSON served with wrong Content-Type
        if not is_json_ct and (is_json_array or is_json_object) and not is_js_ct:
            if len(body.strip()) > 2:
                log_warn(logger, f"XSSI: JSON response without application/json Content-Type at {url}")
                self.results.append(self._result(
                    url,
                    "XSSI — JSON response missing application/json Content-Type",
                    "WARN",
                    detail=(
                        f"The endpoint {url} appears to return JSON but lacks "
                        "'Content-Type: application/json'. "
                        "Missing or wrong Content-Type increases MIME-sniffing risk "
                        "and may allow browsers to treat the response as a script. "
                        "Fix: always set 'Content-Type: application/json' for JSON responses "
                        "alongside 'X-Content-Type-Options: nosniff'. CWE-284."
                    ),
                ))
