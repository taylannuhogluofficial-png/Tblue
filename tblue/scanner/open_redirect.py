"""
Open redirect parameter detection.

Passively identifies redirect-style URL parameters in the page HTML
(links, forms, script URLs) and flags them for review. These parameters
are common targets for phishing campaigns and OAuth token theft.

No injection is performed — this is a pure blue-team inventory check.
The fix is always to validate the redirect destination against a whitelist
of allowed internal paths/domains before redirecting.
"""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

# Parameter names commonly used for redirect destinations
_REDIRECT_PARAMS = {
    "url", "next", "redirect", "redirect_url", "redirect_to", "redirect_uri",
    "return", "return_to", "returnUrl", "returnurl", "return_url",
    "goto", "destination", "dest", "redir", "forward",
    "continue", "proceed", "target", "to", "from", "back",
    "location", "callback", "link", "ref", "referer", "referrer",
    "success_url", "cancel_url", "failure_url", "checkout_url",
}

_PARAM_RE = re.compile(
    r'[?&](' + '|'.join(re.escape(p) for p in sorted(_REDIRECT_PARAMS, key=len, reverse=True)) + r')=([^&"\'\s>]+)',
    re.I
)

# href/action attributes that might contain redirect params
_HREF_RE = re.compile(r'(?:href|action|src)\s*=\s*["\']([^"\']+)["\']', re.I)

_MAX_REPORT = 10  # cap findings per page to avoid noise


class OpenRedirectScanner(BaseScanner):

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        try:
            resp = self.http.get(url)
        except Exception:
            return self.results
        if resp is None:
            return self.results

        found = self._find_redirect_params(resp.text or "", url)

        if not found:
            log_pass(logger, "No open redirect parameters detected")
            self.results.append(self._result(url,
                "Open redirect parameters — none detected",
                "PASS",
                detail="No redirect-style URL parameters were found in page links or forms. "
                       "Checked for: " + ", ".join(sorted(_REDIRECT_PARAMS)[:12]) + " and others."))
        else:
            seen = set()
            count = 0
            for param, example_url in found:
                key = param.lower()
                if key in seen or count >= _MAX_REPORT:
                    continue
                seen.add(key)
                count += 1
                log_warn(logger, f"Open redirect parameter found: {param}")
                self.results.append(self._result(url,
                    f"Open redirect parameter detected — ?{param}=",
                    "WARN",
                    detail=(
                        f"The page contains a URL with a redirect parameter: "
                        f"'{param}' in '{example_url[:120]}'. "
                        f"If the destination is not validated against a whitelist, "
                        f"an attacker can craft a link like: "
                        f"{url.rstrip('/')}?{param}=https://attacker.com "
                        f"— appearing to originate from your trusted domain while "
                        f"redirecting victims to a phishing site or stealing OAuth tokens. "
                        f"Fix: validate redirect destinations against an explicit allowlist "
                        f"of trusted paths (prefer relative paths only). "
                        f"Never redirect to user-supplied absolute URLs."
                    )))
        return self.results

    def _find_redirect_params(self, html: str, base_url: str) -> List[tuple]:
        results = []

        # Check the base URL itself
        for m in _PARAM_RE.finditer(base_url):
            results.append((m.group(1), base_url))

        # Check all href/action/src attributes in HTML
        for href_match in _HREF_RE.finditer(html):
            href = href_match.group(1)
            for m in _PARAM_RE.finditer(href):
                results.append((m.group(1), href))

        # Check inline JS for redirect param patterns
        for m in _PARAM_RE.finditer(html):
            results.append((m.group(1), m.group(0)))

        # Deduplicate by param name
        seen = set()
        deduped = []
        for param, src in results:
            if param.lower() not in seen:
                seen.add(param.lower())
                deduped.append((param, src))
        return deduped
