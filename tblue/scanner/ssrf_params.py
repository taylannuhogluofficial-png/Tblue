"""
SSRF-Prone Parameter Detector.

Passively scans HTML forms and URL query strings for parameter names that are
commonly exploited in Server-Side Request Forgery (SSRF) attacks. No requests
are made to external servers — this is a pure static analysis of page content.

Parameters like ?url=, ?redirect=, ?proxy= are frequent SSRF entry points because
they instruct the server to make an outbound HTTP request, potentially reaching
internal services (AWS metadata, Kubernetes API, Redis, internal admin UIs).

Paid equivalents: Burp Scanner SSRF detection, Detectify SSRF module.
"""

import re
from typing import Any, Dict, FrozenSet, List, Set
from urllib.parse import urlparse, parse_qs

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Parameter names strongly associated with SSRF
_HIGH_RISK: FrozenSet[str] = frozenset({
    "url", "uri", "src", "source", "dest", "destination",
    "redirect", "redirect_url", "redirect_uri",
    "proxy", "proxy_url",
    "fetch", "load", "remote",
    "endpoint", "target", "path",
    "image_url", "img_url", "file_url", "data_url",
    "callback", "webhook", "hook",
    "next", "return", "returnto", "return_to",
    "continue", "back", "forward",
    "link", "ref", "referer",
    "host", "domain", "server",
    "from", "to",
})

# Moderate-risk names — common in pagination, search, navigation
_MEDIUM_RISK: FrozenSet[str] = frozenset({
    "page", "site", "location", "resource", "asset",
    "icon", "logo", "avatar", "photo",
    "import", "export",
})

# Values that look like full URLs (high-confidence SSRF signal)
_URL_VALUE_RE = re.compile(r"^https?://", re.I)


class SSRFParamScanner(BaseScanner):
    """Detect SSRF-prone parameter names in forms and URLs on the page."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        resp = self.http.get(url)
        if not resp:
            return self.results

        body = resp.text or ""
        soup = BeautifulSoup(body, "html.parser")

        high_risk_found: Set[str] = set()
        medium_risk_found: Set[str] = set()
        url_valued: Set[str] = set()     # params that already carry a URL value

        # ── Forms ──────────────────────────────────────────────────────────────
        for form in soup.find_all("form"):
            for inp in form.find_all("input"):
                name  = (inp.attrs.get("name", "") or "").lower().strip()
                value = (inp.attrs.get("value", "") or "").strip()
                _classify(name, value, high_risk_found, medium_risk_found, url_valued)

            for select in form.find_all("select"):
                name = (select.attrs.get("name", "") or "").lower().strip()
                _classify(name, "", high_risk_found, medium_risk_found, url_valued)

            for textarea in form.find_all("textarea"):
                name = (textarea.attrs.get("name", "") or "").lower().strip()
                _classify(name, "", high_risk_found, medium_risk_found, url_valued)

        # ── URL query strings in page links ────────────────────────────────────
        for tag in soup.find_all(href=True):
            href = tag.attrs.get("href", "")
            _scan_query(href, high_risk_found, medium_risk_found, url_valued)

        for tag in soup.find_all(action=True):
            action = tag.attrs.get("action", "")
            _scan_query(action, high_risk_found, medium_risk_found, url_valued)

        # ── Also check the target URL's own query string ───────────────────────
        _scan_query(url, high_risk_found, medium_risk_found, url_valued)

        # ── Emit results ───────────────────────────────────────────────────────
        if url_valued:
            examples = ", ".join(sorted(url_valued)[:5])
            log_fail(logger, f"SSRF-prone params with URL values on {url}: {examples}")
            self.results.append(self._result(
                url, "SSRF — parameter already carries URL value", "FAIL",
                detail=(
                    f"Parameter(s) {examples} appear to accept URL values on {url}. "
                    "If the server fetches these URLs server-side, an attacker can pivot "
                    "to internal services (AWS metadata, Kubernetes API, Redis). "
                    "Fix: validate that URL-valued parameters only accept approved domains; "
                    "use a strict allowlist, never a blocklist."
                )
            ))

        if high_risk_found - url_valued:
            examples = ", ".join(sorted(high_risk_found - url_valued)[:8])
            log_warn(logger, f"SSRF-prone parameter names found on {url}: {examples}")
            self.results.append(self._result(
                url, "SSRF — high-risk parameter names present", "WARN",
                detail=(
                    f"Parameter(s) {examples} have names commonly exploited in SSRF attacks. "
                    "Verify these parameters are not used to trigger server-side HTTP requests. "
                    "Fix: if server-side fetching is required, validate the destination against "
                    "an allowlist of approved hosts; block private IP ranges (RFC1918)."
                )
            ))

        if medium_risk_found and not high_risk_found and not url_valued:
            examples = ", ".join(sorted(medium_risk_found)[:5])
            self.results.append(self._result(
                url, "SSRF — moderate-risk parameter names present", "WARN",
                detail=(
                    f"Parameter(s) {examples} may be used to load remote resources. "
                    "Manually verify these do not trigger server-side HTTP requests to "
                    "attacker-controlled URLs."
                )
            ))

        if not self.results:
            log_pass(logger, f"No SSRF-prone parameters found on {url}")
            self.results.append(self._result(
                url, "SSRF — no high-risk parameters detected", "PASS",
                detail="No known SSRF-prone parameter names found in forms or URLs on this page."
            ))

        return self.results


def _classify(
    name: str,
    value: str,
    high: Set[str],
    medium: Set[str],
    url_valued: Set[str],
) -> None:
    if not name:
        return
    if name in _HIGH_RISK:
        high.add(name)
        if _URL_VALUE_RE.match(value):
            url_valued.add(name)
    elif name in _MEDIUM_RISK:
        medium.add(name)


def _scan_query(href: str, high: Set[str], medium: Set[str], url_valued: Set[str]) -> None:
    try:
        qs = parse_qs(urlparse(href).query)
        for name, values in qs.items():
            _classify(name.lower(), values[0] if values else "", high, medium, url_valued)
    except Exception:
        pass
