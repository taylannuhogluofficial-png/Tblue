"""
XSS reflection scanner.
Tests forms, URL parameters, and HTTP headers for unescaped input reflection.
Uses harmless text markers — no JavaScript payloads.
"""

from typing import List, Dict, Any
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from bs4 import BeautifulSoup
from tblue.scanner.base import BaseScanner
from tblue.constants import TEST_MARKER, TEMPLATE_MARKERS
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

SKIP_TYPES = {"submit", "button", "image", "reset", "file", "hidden", "checkbox", "radio"}

EVENT_ATTRS = frozenset({
    "onclick", "ondblclick", "onmousedown", "onmouseup", "onmouseover",
    "onmouseout", "onmousemove", "onkeydown", "onkeyup", "onkeypress",
    "onload", "onunload", "onabort", "onerror", "onresize", "onscroll",
    "onselect", "onchange", "onsubmit", "onreset", "onfocus", "onblur",
    "oninput", "oninvalid", "onpaste", "oncopy", "oncut",
})

REFLECTION_HEADERS = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Original-URL",
]

# Marker with HTML-special chars to detect partial encoding (< encoded, " not)
_BYPASS_MARKER = 'xssbyp1337"<'


class XSSScanner(BaseScanner):
    """
    Checks if user input is reflected back unescaped in HTML responses.
    Covers: forms (GET/POST), URL parameters, HTTP headers, JSON responses.
    Detects reflection context (script, attribute, event handler, textarea)
    and partial encoding bypasses.
    """

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        resp = self.http.get(url)
        if not resp:
            return self.results

        self._scan_forms(url, resp.text)
        self._scan_url_params(url)
        self._scan_headers(url)
        self._scan_template_injection(url)
        return self.results

    # ── Form scanning ─────────────────────────────────────────────────────────

    def _scan_forms(self, url: str, html: str) -> None:
        soup  = BeautifulSoup(html, "html.parser")
        forms = soup.find_all("form")
        if not forms:
            return

        logger.info(f"Found {len(forms)} form(s) on {url}")

        for i, form in enumerate(forms, 1):
            action      = form.attrs.get("action") or url
            full_action = urljoin(url, action)
            method      = (form.attrs.get("method") or "get").upper()
            data        = self._collect_fields(form)
            if not data:
                continue

            resp = (
                self.http.post(full_action, data)
                if method == "POST"
                else self.http.get(full_action, params=data)
            )
            if not resp:
                continue

            self._evaluate_reflection(resp, full_action, f"Form #{i}", method, list(data.keys()))
            self._check_json_reflection(resp, full_action, f"Form #{i} — JSON reflection", method, list(data.keys()))
            self._check_encoding_bypass(full_action, method, data)

    # ── URL parameter scanning ────────────────────────────────────────────────

    def _scan_url_params(self, url: str) -> None:
        parsed = urlparse(url)
        if not parsed.query:
            return

        params      = parse_qs(parsed.query)
        test_params = {k: TEST_MARKER for k in params}
        test_url    = parsed._replace(query=urlencode(test_params)).geturl()

        resp = self.http.get(test_url)
        if not resp:
            return

        self._evaluate_reflection(resp, url, "URL parameter reflection", "GET", list(params.keys()))
        self._check_json_reflection(resp, url, "URL parameter reflection — JSON", "GET", list(params.keys()))
        self._check_encoding_bypass_params(url, params)

    # ── Header reflection scanning ────────────────────────────────────────────

    def _scan_headers(self, url: str) -> None:
        """Test User-Agent, Referer, X-Forwarded-For and similar headers for reflection."""
        for header_name in REFLECTION_HEADERS:
            resp = self.http.get(url, headers={header_name: TEST_MARKER})
            if not resp or TEST_MARKER not in resp.text:
                continue

            if self._is_encoded(resp.text):
                continue

            contexts = self._detect_reflection_context(resp.text)
            ctx_desc = self._describe_contexts(contexts)
            log_fail(logger, f"{header_name} header reflects unencoded at {url}")
            self.results.append(self._result(
                url, f"Header reflection — {header_name}", "FAIL",
                detail=(
                    f"{header_name} header value reflected back unescaped.{ctx_desc} "
                    "Fix: sanitize and HTML-encode header values before including them "
                    "in any response body."
                )
            ))

    # ── Template injection scanning ───────────────────────────────────────────

    def _scan_template_injection(self, url: str) -> None:
        """Test URL parameters for server-side template injection markers."""
        parsed = urlparse(url)
        if not parsed.query:
            return

        params = parse_qs(parsed.query)

        for tpl_marker, tpl_engine in TEMPLATE_MARKERS:
            tpl_inner   = "xsstpl1337"
            test_url    = parsed._replace(query=urlencode({k: tpl_marker for k in params})).geturl()
            resp        = self.http.get(test_url)
            if not resp:
                continue

            if tpl_inner not in resp.text:
                log_pass(logger, f"Template marker ({tpl_engine}) not in response at {url}")
                self.results.append(self._result(
                    url, f"Template injection — {tpl_engine}", "PASS",
                    fields=list(params.keys()),
                ))
            elif tpl_marker not in resp.text:
                # delimiters consumed but inner text present — template engine processed it
                log_fail(logger, f"Template delimiters consumed ({tpl_engine}) at {url} — possible SSTI")
                self.results.append(self._result(
                    url, f"Template injection — {tpl_engine}", "FAIL",
                    fields=list(params.keys()),
                    detail=(
                        f"Template delimiters stripped from '{tpl_marker}' — the {tpl_engine} "
                        "template engine appears to have processed the input. "
                        "This indicates a potential SSTI vulnerability. "
                        "Fix: never pass user input directly into template rendering calls."
                    )
                ))
            else:
                # full marker reflected unchanged
                log_warn(logger, f"Template marker ({tpl_engine}) reflected unchanged at {url}")
                self.results.append(self._result(
                    url, f"Template injection — {tpl_engine}", "WARN",
                    fields=list(params.keys()),
                    detail=(
                        f"Template syntax '{tpl_marker}' reflected unchanged. "
                        "If this output is inserted into another template server-side, "
                        "it could enable SSTI. Verify user input never reaches a template engine."
                    )
                ))

    # ── Shared reflection evaluation ──────────────────────────────────────────

    def _evaluate_reflection(
        self,
        resp,
        url: str,
        label: str,
        method: str = "GET",
        fields: List[str] = None,
    ) -> None:
        """Check if TEST_MARKER is present in the response, classify context, and emit result."""
        if TEST_MARKER in resp.text:
            encoded  = self._is_encoded(resp.text)
            contexts = self._detect_reflection_context(resp.text)
            if encoded:
                log_pass(logger, f"{label} reflects but is HTML-encoded at {url}")
                self.results.append(self._result(
                    url, label, "PASS",
                    method=method, fields=fields or [],
                    detail="Input reflected but appears HTML-encoded — check manually to confirm."
                ))
            else:
                ctx_desc = self._describe_contexts(contexts)
                log_fail(logger, f"{label} reflects unencoded at {url} ({method})")
                self.results.append(self._result(
                    url, label, "FAIL",
                    method=method, fields=fields or [],
                    detail=(
                        f"Input reflected back unescaped.{ctx_desc} "
                        "Fix: encode all output using your framework's escaping functions "
                        "and add a Content-Security-Policy header."
                    )
                ))
        else:
            log_pass(logger, f"{label} safe at {url}")
            self.results.append(self._result(
                url, label, "PASS",
                method=method, fields=fields or [],
            ))

    def _check_json_reflection(
        self,
        resp,
        url: str,
        label: str,
        method: str = "GET",
        fields: List[str] = None,
    ) -> None:
        """Flag if TEST_MARKER appears in a JSON response body."""
        content_type = resp.headers.get("content-type", "")
        if "json" not in content_type.lower() or TEST_MARKER not in resp.text:
            return

        log_fail(logger, f"{label} marker in JSON response at {url}")
        self.results.append(self._result(
            url, label, "FAIL",
            method=method, fields=fields or [],
            detail=(
                "Input reflected inside a JSON response body. If this value is later injected "
                "into the DOM via innerHTML or similar, it creates an XSS vector. "
                "Fix: sanitize API response values and never insert JSON content into innerHTML."
            )
        ))

    def _check_encoding_bypass(self, url: str, method: str, data: Dict[str, str]) -> None:
        """Detect partial HTML encoding: < encoded but \" not → attribute injection possible."""
        bypass_data = {k: _BYPASS_MARKER for k in data}
        resp = (
            self.http.post(url, bypass_data)
            if method == "POST"
            else self.http.get(url, params=bypass_data)
        )
        if not resp or "xssbyp1337" not in resp.text:
            return

        lt_encoded   = "&lt;" in resp.text
        quot_encoded = any(e in resp.text for e in ("&quot;", "&#34;", "&#x22;"))

        if lt_encoded and not quot_encoded:
            log_fail(logger, f"Encoding bypass: < encoded but \" not at {url}")
            self.results.append(self._result(
                url, "XSS — encoding bypass (attribute context)", "FAIL",
                method=method, fields=list(data.keys()),
                detail=(
                    "< is HTML-encoded but \" is not, making attribute-context XSS possible: "
                    '<input value="...[injection here]">. '
                    "Fix: use ENT_QUOTES (PHP) or your framework's attribute-safe escape "
                    "to encode both < and \" in all output contexts."
                )
            ))

    def _check_encoding_bypass_params(self, url: str, params: Dict) -> None:
        """Encoding bypass check for URL parameters."""
        parsed   = urlparse(url)
        test_url = parsed._replace(
            query=urlencode({k: _BYPASS_MARKER for k in params})
        ).geturl()
        resp = self.http.get(test_url)
        if not resp or "xssbyp1337" not in resp.text:
            return

        lt_encoded   = "&lt;" in resp.text
        quot_encoded = any(e in resp.text for e in ("&quot;", "&#34;", "&#x22;"))

        if lt_encoded and not quot_encoded:
            log_fail(logger, f"URL param encoding bypass at {url}")
            self.results.append(self._result(
                url, "URL parameter — encoding bypass (attribute context)", "FAIL",
                fields=list(params.keys()),
                detail=(
                    "URL parameter: < is encoded but \" is not — attribute injection still exploitable. "
                    "Fix: use attribute-safe encoding (ENT_QUOTES) for all reflected URL parameters."
                )
            ))

    # ── Context detection ─────────────────────────────────────────────────────

    def _detect_reflection_context(self, html: str) -> List[str]:
        """
        Classify where TEST_MARKER appears in the HTML.
        Returns list of context names: script, textarea, event_handler, attribute, html_body.
        """
        contexts: List[str] = []
        soup = BeautifulSoup(html, "html.parser")

        for script in soup.find_all("script"):
            if script.string and TEST_MARKER in script.string:
                if "script" not in contexts:
                    contexts.append("script")

        for textarea in soup.find_all("textarea"):
            if textarea.string and TEST_MARKER in textarea.string:
                if "textarea" not in contexts:
                    contexts.append("textarea")

        for tag in soup.find_all(True):
            for attr, val in tag.attrs.items():
                val_str = " ".join(val) if isinstance(val, list) else str(val)
                if TEST_MARKER in val_str:
                    ctx = "event_handler" if attr.lower() in EVENT_ATTRS else "attribute"
                    if ctx not in contexts:
                        contexts.append(ctx)

        for text_node in soup.find_all(string=True):
            parent = getattr(text_node.parent, "name", None)
            if TEST_MARKER in str(text_node) and parent not in ("script", "textarea", "style"):
                if "html_body" not in contexts:
                    contexts.append("html_body")

        return contexts

    def _describe_contexts(self, contexts: List[str]) -> str:
        desc_map = {
            "script":        "Reflected inside a <script> block — character-encoding bypasses may apply.",
            "textarea":      "Reflected inside <textarea> — closing the tag enables injection.",
            "event_handler": "Reflected in an event handler attribute (e.g. onclick) — immediately executable.",
            "attribute":     "Reflected inside an HTML attribute — break out with quote characters.",
            "html_body":     "Reflected in HTML body context.",
        }
        if not contexts:
            return ""
        return " Context: " + " ".join(desc_map.get(c, c) for c in contexts)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _collect_fields(self, form) -> Dict[str, str]:
        data: Dict[str, str] = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name     = inp.attrs.get("name")
            inp_type = inp.attrs.get("type", "text").lower()
            if name and inp_type not in SKIP_TYPES:
                data[name] = TEST_MARKER
        return data

    def _is_encoded(self, response_text: str) -> bool:
        encoded_marker = TEST_MARKER.replace("<", "&lt;").replace(">", "&gt;")
        return encoded_marker in response_text and TEST_MARKER not in response_text.replace(
            "&lt;", "<"
        ).replace("&gt;", ">")
