"""
DOM pattern scanner.
Flags risky JavaScript patterns in page source.
Also detects external scripts without subresource integrity,
unsafe postMessage handlers, open redirect sinks, and prototype pollution.
"""

import re
from typing import List, Dict, Any
from bs4 import BeautifulSoup
from tblue.scanner.base import BaseScanner
from tblue.definitions.dom_risks import DOM_RISKS
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

# postMessage listener without origin check
_POSTMSG_NO_ORIGIN = re.compile(
    r"addEventListener\s*\(\s*['\"]message['\"].*?function.*?\)",
    re.S,
)
_ORIGIN_CHECK = re.compile(r"event\.origin|e\.origin|msg\.origin", re.I)

# Open redirect: location assigned from a variable that may come from input.
# Negative lookahead uses \s* inside to account for zero-width match of outer \s*.
_OPEN_REDIRECT = re.compile(
    r"(?:window\.location|location\.href|location\.replace)\s*=\s*"
    r"(?!\s*['\"]/|\s*['\"]https?://[a-z])",
    re.I,
)


class DOMScanner(BaseScanner):
    """
    Scans page source for risky JavaScript patterns,
    external scripts without SRI, unsafe postMessage handlers,
    and open redirect sinks.
    """

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        resp = self.http.get(url)
        if not resp:
            return self.results

        self._check_dom_patterns(url, resp.text)
        self._check_external_scripts(url, resp.text)
        self._check_postmessage_origins(url, resp.text)
        self._check_open_redirects(url, resp.text)
        return self.results

    def _check_dom_patterns(self, url: str, html: str) -> None:
        """Check for risky JavaScript patterns in page source."""
        found = [p for p in DOM_RISKS if p["pattern"] in html]

        if found:
            patterns_str = ", ".join(p["pattern"] for p in found)
            log_warn(logger, f"DOM risk patterns on {url}: {patterns_str}")
            self.results.append({
                "url":      url,
                "type":     "DOM risk pattern",
                "status":   "WARN",
                "patterns": found,
                "detail": (
                    f"Found {len(found)} risky pattern(s) — review manually. "
                    "These are not confirmed vulnerabilities."
                ),
            })
        else:
            log_pass(logger, f"No DOM risks on {url}")
            self.results.append({
                "url": url, "type": "DOM risk pattern",
                "status": "PASS", "patterns": [],
                "detail": "No risky DOM patterns found.",
            })

    def _check_external_scripts(self, url: str, html: str) -> None:
        """
        Check external scripts for Subresource Integrity (SRI).
        External scripts without SRI can be tampered with by CDN providers.
        """
        soup = BeautifulSoup(html, "html.parser")
        external = [
            s for s in soup.find_all("script", src=True)
            if s.attrs.get("src", "").startswith("http")
        ]

        if not external:
            return

        missing = [s.attrs["src"] for s in external if not s.attrs.get("integrity")]

        if missing:
            log_warn(logger, f"{len(missing)} external script(s) missing SRI on {url}")
            self.results.append(self._result(
                url, "DOM — external scripts without SRI", "WARN",
                detail=(
                    f"{len(missing)} external script(s) lack Subresource Integrity checks. "
                    f"Scripts: {', '.join(missing[:3])}. "
                    "Fix: add integrity and crossorigin attributes. "
                    "Generate hashes at https://www.srihash.org"
                )
            ))
        else:
            log_pass(logger, f"All external scripts have SRI on {url}")
            self.results.append(self._result(
                url, "DOM — external scripts SRI", "PASS",
                detail="All external scripts have SRI integrity attributes."
            ))

    def _check_postmessage_origins(self, url: str, html: str) -> None:
        """Check for postMessage event listeners that skip origin validation."""
        soup    = BeautifulSoup(html, "html.parser")
        scripts = [s.string or "" for s in soup.find_all("script") if not s.attrs.get("src")]
        js_body = "\n".join(scripts)

        if "addEventListener" not in js_body or "message" not in js_body:
            return

        # Look for message listeners without any origin check nearby
        listeners = _POSTMSG_NO_ORIGIN.findall(js_body)
        if listeners and not _ORIGIN_CHECK.search(js_body):
            log_warn(logger, f"postMessage listener without origin check on {url}")
            self.results.append(self._result(
                url, "DOM — postMessage without origin validation", "WARN",
                detail=(
                    "A postMessage event listener was found but no event.origin check is visible. "
                    "Without origin validation, any cross-origin page can send messages that "
                    "your handler will process. "
                    "Fix: always check event.origin against an allowlist before processing "
                    "postMessage data."
                )
            ))

    def _check_open_redirects(self, url: str, html: str) -> None:
        """Check for open redirect patterns where location is assigned from a variable."""
        soup    = BeautifulSoup(html, "html.parser")
        scripts = [s.string or "" for s in soup.find_all("script") if not s.attrs.get("src")]
        js_body = "\n".join(scripts)

        if _OPEN_REDIRECT.search(js_body):
            log_warn(logger, f"Potential open redirect pattern in JS on {url}")
            self.results.append(self._result(
                url, "DOM — potential open redirect", "WARN",
                detail=(
                    "window.location or location.href is assigned from a variable, "
                    "which may allow open redirect if the variable contains user-controlled data. "
                    "Fix: validate and allowlist redirect URLs — never redirect to arbitrary "
                    "user-supplied URLs."
                )
            ))
