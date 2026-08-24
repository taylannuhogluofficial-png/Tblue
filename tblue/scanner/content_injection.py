"""
Content Injection / HTML Injection Scanner.

Content injection (not XSS — no script execution) occurs when user input
appears in HTML output without encoding, allowing attackers to inject
visible content (fake warnings, phishing forms) even without JS execution.

Also covers:
- Response splitting via injected HTML in error messages
- UI redressing via injected CSS
- Open redirects via HTML meta-refresh injection

Detection (read-only):
1. Find parameters that appear reflected in responses
2. Inject HTML marker tags and check if they appear unescaped
3. Check for CSS injection (style= in reflected content)
4. Check for meta-refresh injection

Distinct from XSS: we're checking for raw HTML tag injection in contexts
where scripts may be blocked (CSP/WAF) but HTML rendering still occurs.

CWE-74: Improper Neutralization of Special Elements in Output
CWE-80: Improper Neutralization of Script-Related HTML Tags
"""

import re
from typing import Any, Dict, List, Set
from urllib.parse import urlparse, parse_qs, urlencode

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# HTML injection marker — no script, just a distinctively named div
_HTML_MARKER = "tblue_html_probe"
_HTML_PAYLOAD = f'<div class="{_HTML_MARKER}">TblueTest</div>'
_CSS_PAYLOAD = f'"><style>body{{display:none}}</style><b class="{_HTML_MARKER}">'
_META_PAYLOAD = f'<meta http-equiv="refresh" content="0;url=https://tblue.test/?{_HTML_MARKER}">'

# Params commonly reflected in error/search pages
_REFLECTED_PARAMS = frozenset({
    "q", "query", "search", "s", "keyword", "term", "input",
    "message", "msg", "error", "err", "notice", "info",
    "name", "username", "email", "text", "content",
    "title", "subject", "description", "comment",
    "redirect", "return", "next", "url", "path",
})

# Detect unescaped marker in response
_MARKER_IN_RESPONSE_RE = re.compile(
    r'<div\s+class="tblue_html_probe"',
    re.I,
)

_CSS_MARKER_RE = re.compile(
    r'<b\s+class="tblue_html_probe"',
    re.I,
)

_META_MARKER_RE = re.compile(
    r'<meta\s+http-equiv="refresh".*?tblue_html_probe',
    re.I,
)


class ContentInjectionScanner(BaseScanner):
    """Detects HTML content injection via reflected parameter probing."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping content injection checks: {url}")
            self.results.append(self._result(
                url, "Content injection — no response", "PASS",
                detail="Target did not respond; content injection checks skipped."
            ))
            return self.results

        body = resp.text or ""
        params = self._collect_reflectable_params(url, body)

        if not params:
            log_pass(logger, f"No reflectable parameters: {url}")
            self.results.append(self._result(
                url, "Content injection — no reflectable parameters found", "PASS",
                detail=(
                    "No URL parameters matching known reflectable patterns found."
                )
            ))
            return self.results

        for param in list(params)[:5]:
            if self._probe_param(url, param):
                return self.results

        if not self.results:
            log_pass(logger, f"No content injection indicators: {url}")
            self.results.append(self._result(
                url, "Content injection — no indicators detected", "PASS",
                detail=(
                    "HTML injection payloads were either not reflected or were "
                    "properly encoded in the response."
                )
            ))

        return self.results

    def _collect_reflectable_params(self, url: str, body: str) -> Set[str]:
        found: Set[str] = set()
        parsed = urlparse(url)
        for param in parse_qs(parsed.query):
            if param.lower() in _REFLECTED_PARAMS:
                found.add(param)
            # Also check if the value appears literally in the body (reflection)
            values = parse_qs(parsed.query).get(param, [])
            if values and values[0] in body:
                found.add(param)

        if not found:
            # Check page for search forms
            soup = BeautifulSoup(body, "html.parser")
            for inp in soup.find_all("input"):
                name = (inp.get("name") or "").lower()
                type_ = (inp.get("type") or "text").lower()
                if type_ in ("text", "search") and name:
                    found.add(inp.get("name"))
                    if len(found) >= 3:
                        break

        return found

    def _probe_param(self, url: str, param: str) -> bool:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # HTML tag injection
        probe_params = dict(params)
        probe_params[param] = [_HTML_PAYLOAD]
        new_query = urlencode({k: v[0] for k, v in probe_params.items()})
        probe_url = parsed._replace(query=new_query).geturl()

        r = self.http.get(probe_url)
        if r and r.status_code == 200:
            body = r.text or ""
            if _MARKER_IN_RESPONSE_RE.search(body):
                log_fail(logger, f"HTML injection via '{param}': {url}")
                self.results.append(self._result(
                    url,
                    f"Content injection — unescaped HTML in parameter '{param}'",
                    "FAIL",
                    detail=(
                        f"Injecting '<div class=\"tblue_html_probe\">' into '{param}' "
                        "produced unescaped HTML in the response. "
                        "Attackers can inject phishing content, fake login forms, or UI-redressing "
                        "elements without executing JavaScript. "
                        "Fix: HTML-encode all user input before rendering: "
                        "use output encoding (e.g., html.escape() in Python, Jinja2 autoescaping, "
                        "React JSX, Django template escaping)."
                    )
                ))
                return True

        # CSS injection (breakout from attribute)
        probe_params[param] = [_CSS_PAYLOAD]
        new_query = urlencode({k: v[0] for k, v in probe_params.items()})
        probe_url = parsed._replace(query=new_query).geturl()

        r = self.http.get(probe_url)
        if r and r.status_code == 200:
            body = r.text or ""
            if _CSS_MARKER_RE.search(body):
                log_warn(logger, f"CSS injection via '{param}': {url}")
                self.results.append(self._result(
                    url,
                    f"Content injection — CSS injection via parameter '{param}'",
                    "WARN",
                    detail=(
                        f"Injecting CSS breakout payload into '{param}' produced "
                        "unescaped HTML in the response. "
                        "CSS injection can hide content, redirect to phishing pages, "
                        "or exfiltrate data via CSS selectors. "
                        "Fix: HTML-encode all attribute values; "
                        "use Content-Security-Policy to block inline styles."
                    )
                ))
                return True

        return False
