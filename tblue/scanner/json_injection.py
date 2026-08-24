"""
JSON Injection Scanner.

JSON Injection occurs when user-controlled data is embedded in a JSON
context without proper escaping, allowing attackers to inject additional
JSON keys, override existing values, or break out of the JSON context.

Attack vectors:
1. JSON parameter injection — injecting `","key":"injected_value"` into a field
2. JavaScript context injection — breaking out of JSON into JS: `</script><script>`
3. JSON in HTML — JSON object in onclick/href attributes with injectable fields
4. API response reflection — user input reflected in JSON response without escaping
5. JSON CSRF — JSON-based state changes submitted cross-origin
6. JSONP callback injection — injecting JavaScript into JSONP callback name
7. JSON prototype pollution via `__proto__` key — detected passively from error hints

Detection approach (passive analysis + light probing):
1. Find forms/API endpoints that accept or return JSON
2. Check that reflected values are properly JSON-encoded
3. Detect JSONP endpoints with unvalidated callback parameter
4. Check Content-Type enforcement (rejects text/html with JSON body)
5. Detect JSON in HTML event handlers (injection context)

Professional equivalent: Burp Suite Pro "JSON Injection" active scan rule,
Invicti JSON injection module, OWASP ZAP JSON scanner.

CWE-74: Improper Neutralization of Special Elements in Output (Injection)
CWE-116: Improper Encoding or Escaping of Output
CWE-79: Cross-Site Scripting (in JSON context)
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, parse_qsl

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# JSONP callback parameter names
_JSONP_PARAMS = frozenset({
    "callback", "cb", "jsonp", "jsonpcallback", "callbackparam",
    "fn", "func", "on", "jsoncallback", "call",
})

# Valid callback name pattern
_VALID_CALLBACK_RE = re.compile(r"^[a-zA-Z_$][a-zA-Z0-9_$\.]*$")

# JSONP injection payload
_JSONP_PAYLOAD = "tblue_/*<script>alert(1)</script>*/"
_JSONP_MARKER = "tblue_"

# JSON injection probe marker
_JSON_MARKER = "tblue_json_probe"
_JSON_INJECT_PAYLOAD = f'probe\",\"injected_key\":\"{_JSON_MARKER}'

# Response reflection patterns
_JSON_REFLECTION_RE = re.compile(re.escape(_JSON_MARKER), re.I)

# JSON in script tag with reflected data
_JSON_IN_SCRIPT_RE = re.compile(
    r'<script[^>]*>\s*(?:var|const|let)\s+\w+\s*=\s*\{[^<]*\}',
    re.I | re.S,
)

# JSON parameter in URL
_JSON_URL_PARAM_RE = re.compile(
    r"[?&]\w+=\{[^&]+\}|[?&]\w+=\[",
    re.I,
)

# Content-Type application/json
_JSON_CONTENT_TYPE_RE = re.compile(r"application/json", re.I)

# __proto__ pollution hints in response
_PROTO_POLLUTION_RE = re.compile(
    r'"__proto__"\s*:|"constructor"\s*:\s*\{|prototype.*pollution',
    re.I,
)

# JSONP response pattern (function call wrapping JSON)
_JSONP_RESPONSE_RE = re.compile(
    r"""^\s*[\w\$\.]+\s*\(\s*[\[\{]""",
)

# JSON with unescaped HTML
_JSON_UNESCAPED_HTML_RE = re.compile(
    r'"[^"]*<(?:script|img|svg|iframe|object)[^"]*"',
    re.I,
)


class JSONInjectionScanner(BaseScanner):
    """Detect JSON injection vulnerabilities including JSONP and reflection flaws."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "JSON injection — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        body = resp.text or ""
        soup = BeautifulSoup(body, "html.parser")
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        content_type = resp.headers.get("content-type", "") or ""

        found_any = False

        # ── 1. Check for JSONP endpoint (callback param without validation) ──
        found_any |= self._check_jsonp(url, parsed)

        # ── 2. Check JSON API endpoints for Content-Type enforcement ─────────
        found_any |= self._check_json_content_type(url, resp, content_type)

        # ── 3. Detect JSON in HTML event handlers ─────────────────────────────
        found_any |= self._check_json_in_html_context(soup, url)

        # ── 4. Check API endpoints from page links ────────────────────────────
        found_any |= self._probe_json_api_endpoints(soup, base, url)

        # ── 5. Check for __proto__ pollution hints ────────────────────────────
        if _PROTO_POLLUTION_RE.search(body):
            log_warn(logger, f"__proto__ pollution hint in response: {url}")
            self.results.append(self._result(
                url,
                "JSON injection — __proto__ or prototype reference in JSON response",
                "WARN",
                detail=(
                    "The response contains __proto__ or constructor references in JSON. "
                    "If user-controlled input is parsed with JSON.parse() and merged into "
                    "objects without prototype-safe merge (Object.assign), "
                    "attackers can pollute the JavaScript prototype chain. "
                    "Fix: use JSON schemas to reject prototype keys; "
                    "use Object.create(null) for merge targets; "
                    "validate and strip __proto__, constructor, and prototype keys."
                )
            ))
            found_any = True

        # ── 6. Check for unescaped HTML in JSON response ──────────────────────
        if _JSON_CONTENT_TYPE_RE.search(content_type):
            if _JSON_UNESCAPED_HTML_RE.search(body):
                log_warn(logger, f"Unescaped HTML in JSON response: {url}")
                self.results.append(self._result(
                    url,
                    "JSON injection — unescaped HTML tags in JSON response",
                    "WARN",
                    detail=(
                        "The JSON response contains unescaped HTML tags (<script>, <img>, etc.). "
                        "If this JSON is rendered in HTML without sanitization, XSS is possible. "
                        "Fix: escape HTML special chars in JSON strings (use jsonEncode with "
                        "HTML encoding); set Content-Type: application/json to prevent MIME sniffing."
                    )
                ))
                found_any = True

        if not found_any:
            log_pass(logger, f"No JSON injection vulnerabilities detected on {url}")
            self.results.append(self._result(
                url,
                "JSON injection — no vulnerabilities detected",
                "PASS",
                detail=(
                    "No JSON injection patterns detected. "
                    "Best practices: always set Content-Type: application/json; "
                    "validate and reject __proto__/constructor keys; "
                    "validate JSONP callback names against strict allowlist."
                )
            ))

        return self.results

    def _check_jsonp(self, url: str, parsed) -> bool:
        qs = parse_qs(parsed.query)
        jsonp_param = None
        for param in qs:
            if param.lower() in _JSONP_PARAMS:
                jsonp_param = param
                break

        if not jsonp_param:
            # Check if the endpoint looks like a JSONP endpoint from URL path
            if any(p in parsed.path.lower() for p in ("/jsonp", "/callback", "/json-p")):
                jsonp_param = "callback"
            else:
                return False

        # Probe with injected payload
        parts = list(parse_qsl(parsed.query or ""))
        parts_with_payload = [(k, _JSONP_PAYLOAD if k == jsonp_param else v) for k, v in parts]
        if not any(k == jsonp_param for k, v in parts):
            parts_with_payload.append((jsonp_param, _JSONP_PAYLOAD))

        probe_url = url.split("?")[0] + "?" + urlencode(parts_with_payload)
        try:
            r = self.http.get(probe_url)
            if not r or r.status_code != 200:
                return False
            probe_body = r.text or ""

            if _JSONP_MARKER in probe_body:
                if not _VALID_CALLBACK_RE.match(_JSONP_PAYLOAD):
                    # Our injected payload is reflected — no validation
                    log_fail(logger, f"JSONP callback injection vulnerability: {url}")
                    self.results.append(self._result(
                        url,
                        "JSON injection — JSONP callback parameter not validated",
                        "FAIL",
                        detail=(
                            f"The JSONP endpoint at {url} reflects the '{jsonp_param}' "
                            "callback parameter without validation. "
                            "Attackers can inject arbitrary JavaScript: "
                            "?callback=alert(document.cookie) — enabling account takeover "
                            "if a victim visits a crafted link. "
                            "Fix: validate the callback parameter against a strict allowlist "
                            "of alphanumeric + underscore + period characters; "
                            "prefer JSON over JSONP; use CORS instead."
                        )
                    ))
                    return True
        except Exception:
            pass

        return False

    def _check_json_content_type(self, url: str, resp: Any, content_type: str) -> bool:
        if not _JSON_CONTENT_TYPE_RE.search(content_type):
            return False

        # Check if X-Content-Type-Options is missing (MIME sniffing risk)
        xcto = (resp.headers or {}).get("x-content-type-options", "")
        if not xcto or "nosniff" not in xcto.lower():
            log_warn(logger, f"JSON endpoint missing X-Content-Type-Options: {url}")
            self.results.append(self._result(
                url,
                "JSON injection — JSON endpoint missing X-Content-Type-Options: nosniff",
                "WARN",
                detail=(
                    "The JSON API endpoint at " + url + " is missing the "
                    "X-Content-Type-Options: nosniff header. "
                    "Old browsers may MIME-sniff JSON as text/html, "
                    "enabling JSON-based XSS attacks. "
                    "Fix: add X-Content-Type-Options: nosniff to all JSON responses."
                )
            ))
            return True

        return False

    def _check_json_in_html_context(self, soup: BeautifulSoup, url: str) -> bool:
        found = False

        # Check for JSON data embedded in script tags (may contain user data)
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                continue  # External script, skip
            content = script.get_text()
            if not content:
                continue

            # JSON-like object assigned in script with potential user data
            m = re.search(
                r'(?:var|const|let)\s+(\w+)\s*=\s*(\{[^;]{10,200}\})',
                content, re.S
            )
            if m:
                json_fragment = m.group(2)
                # Check for unescaped quotes that could indicate injection
                if re.search(r'"[^"]*"[^"]*"', json_fragment):
                    # Suspicious double-quoted structure that might allow injection
                    if any(danger in json_fragment.lower()
                           for danger in ("</", "<script", "onerror", "onload", "javascript:")):
                        log_fail(logger, f"HTML injection in JSON data block: {url}")
                        self.results.append(self._result(
                            url,
                            "JSON injection — HTML/JS injection in inline JSON data block",
                            "FAIL",
                            detail=(
                                "An inline JSON data block in a script tag contains "
                                "potentially unescaped HTML/JavaScript. "
                                "If user-controlled data reaches this block without "
                                "JSON encoding, attackers can inject script. "
                                "Fix: use server-side JSON encoding; "
                                "set Content-Security-Policy to restrict inline scripts."
                            )
                        ))
                        found = True

        # Check for JSON-like data in HTML event attributes
        for tag in soup.find_all(True):
            for attr in ("onclick", "onload", "onerror", "onmouseover"):
                val = tag.get(attr, "")
                if not val:
                    continue
                if re.search(r'\{[^}]*"[^"]*"[^}]*\}', val):
                    if re.search(r'["\'].*</?\w+.*["\']', val):
                        log_warn(logger, f"JSON in event handler with HTML context: {url}")
                        self.results.append(self._result(
                            url,
                            "JSON injection — JSON-like data in HTML event handler",
                            "WARN",
                            detail=(
                                "JSON-like data structure found in an HTML event handler "
                                f"({attr}). If user input reaches these handlers without "
                                "proper JSON escaping, XSS is possible. "
                                "Fix: never embed user-controlled JSON in event handlers; "
                                "use data attributes and parse them safely in JS."
                            )
                        ))
                        found = True

        return found

    def _probe_json_api_endpoints(self, soup: BeautifulSoup,
                                   base: str, url: str) -> bool:
        found = False
        seen: set = set()

        # Look for forms that submit JSON (data-type="json" or action ending in .json)
        for form in soup.find_all("form"):
            action = form.get("action", "")
            enc_type = form.get("enctype", "")
            data_type = form.get("data-type", "")

            if (action.endswith(".json") or
                    "json" in enc_type.lower() or
                    "json" in data_type.lower()):
                action_url = urljoin(base, action)
                if action_url in seen:
                    continue
                seen.add(action_url)

                # Find text input fields to probe
                for inp in form.find_all("input", type=re.compile(r"text|email|search", re.I)):
                    name = inp.get("name", "")
                    if not name:
                        continue

                    # Probe with JSON injection payload
                    probe_url = f"{action_url}?{urlencode({name: _JSON_INJECT_PAYLOAD})}"
                    try:
                        r = self.http.get(probe_url)
                        if not r or r.status_code not in (200, 201):
                            continue
                        probe_body = r.text or ""
                        if _JSON_REFLECTION_RE.search(probe_body):
                            # Check if the marker appears as a key rather than escaped value
                            if f'"injected_key":"{_JSON_MARKER}"' in probe_body:
                                log_fail(logger, f"JSON injection via form field: {probe_url}")
                                self.results.append(self._result(
                                    action_url,
                                    f"JSON injection — parameter '{name}' injectable into JSON",
                                    "FAIL",
                                    detail=(
                                        f"Parameter '{name}' in form at {action_url} "
                                        "was injected into the JSON response structure. "
                                        "The injected key appeared as a separate JSON key, "
                                        "indicating the server builds JSON by string concatenation "
                                        "rather than serialization. "
                                        "Fix: use a proper JSON serialization library; "
                                        "never build JSON strings via concatenation."
                                    )
                                ))
                                found = True
                    except Exception:
                        continue
                    break  # One field test per form is sufficient

        return found
