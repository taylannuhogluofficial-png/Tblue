"""
Iframe Sandbox Security Scanner.

The HTML <iframe sandbox> attribute restricts what embedded content can do.
Misconfigurations create security bypasses:

  1. allow-same-origin + allow-scripts together — this combination defeats
     the sandbox entirely: the iframe can read the parent's DOM and exfiltrate
     data. It's a well-documented sandbox escape.

  2. Missing sandbox on cross-origin iframes — third-party iframes without
     sandbox can execute scripts, navigate the top frame, and access storage
     in the embedding origin's context.

  3. allow-top-navigation without allow-top-navigation-by-user-activation —
     allows the iframe to redirect the top browsing context without user
     gesture, enabling clickjacking-style navigation attacks.

  4. allow-forms in iframes loading third-party content — third-party iframes
     with form submission capability can phish users by submitting to their
     own servers.

  5. allow-popups — can open popups that spoof the parent page.

Read-only.

CWE-693: Protection Mechanism Failure
CWE-1021: Improper Restriction of Rendered UI Layers or Frames
"""

import re
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn

logger = get_logger(__name__)

_IFRAME_RE = re.compile(r'<iframe[^>]*>', re.I | re.S)
_SRC_RE = re.compile(r'\bsrc\s*=\s*["\']([^"\']+)["\']', re.I)
_SANDBOX_RE = re.compile(r'\bsandbox\s*=\s*["\']([^"\']*)["\']', re.I)


def _parse_sandbox_tokens(sandbox_val: str) -> Set[str]:
    return {t.strip().lower() for t in sandbox_val.split() if t.strip()}


def _check_iframe(iframe_html: str, page_host: str, page_url: str) -> List[Dict]:
    findings = []

    src_m = _SRC_RE.search(iframe_html)
    src = src_m.group(1) if src_m else ""
    is_cross_origin = False
    if src and not src.startswith("#") and not src.startswith("javascript"):
        try:
            iframe_host = urlparse(src).netloc
            if iframe_host and iframe_host != page_host:
                is_cross_origin = True
        except Exception:
            pass

    sandbox_m = _SANDBOX_RE.search(iframe_html)
    if not sandbox_m:
        if is_cross_origin:
            findings.append({
                "type": "iframe-cross-origin-no-sandbox",
                "status": "WARN",
                "detail": (
                    f"Cross-origin iframe (src={src!r}) at {page_url} has no sandbox attribute.\n\n"
                    f"Unsandboxed third-party iframes can run arbitrary scripts, navigate "
                    f"the top browsing context, and access storage in the embedding origin.\n\n"
                    f"Fix: add sandbox='allow-scripts allow-same-origin' (or stricter) "
                    f"to all third-party iframes."
                ),
            })
        return findings

    tokens = _parse_sandbox_tokens(sandbox_m.group(1))

    # The classic sandbox escape
    if "allow-same-origin" in tokens and "allow-scripts" in tokens:
        findings.append({
            "type": "iframe-sandbox-escape-same-origin-plus-scripts",
            "status": "FAIL",
            "detail": (
                f"Iframe at {page_url} has both allow-same-origin and allow-scripts.\n\n"
                f"This combination completely defeats the sandbox: the iframe script "
                f"can access its own document (same-origin), then remove or modify the "
                f"sandbox attribute on itself, escaping all restrictions.\n\n"
                f"Fix: never combine allow-same-origin and allow-scripts unless "
                f"the iframe content is fully trusted and same-domain."
            ),
        })

    if "allow-top-navigation" in tokens and "allow-top-navigation-by-user-activation" not in tokens:
        findings.append({
            "type": "iframe-sandbox-allow-top-navigation-without-gesture",
            "status": "WARN",
            "detail": (
                f"Iframe at {page_url} has allow-top-navigation without "
                f"allow-top-navigation-by-user-activation.\n\n"
                f"The iframe can redirect the top frame without a user gesture, "
                f"enabling navigation-based phishing attacks.\n\n"
                f"Fix: use allow-top-navigation-by-user-activation instead, which "
                f"requires a user click before navigation."
            ),
        })

    if is_cross_origin and "allow-forms" in tokens:
        findings.append({
            "type": "iframe-sandbox-cross-origin-allow-forms",
            "status": "WARN",
            "detail": (
                f"Cross-origin iframe (src={src!r}) at {page_url} has allow-forms.\n\n"
                f"Third-party content with form submission capability can render "
                f"credential-harvesting forms that submit to attacker-controlled servers.\n\n"
                f"Fix: remove allow-forms from third-party iframes unless specifically required."
            ),
        })

    return findings


class IframeSandboxSecurityScanner(BaseScanner):
    """Checks iframes for sandbox misconfigurations including the classic escape."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Iframe Sandbox — target unreachable", "PASS",
                detail="No response; iframe sandbox check skipped."))
            return self.results

        body = resp.text or ""
        parsed = urlparse(url)
        page_host = parsed.netloc
        found = False
        seen_types: set = set()

        for iframe_html in _IFRAME_RE.findall(body):
            for f in _check_iframe(iframe_html, page_host, url):
                if f["type"] not in seen_types:
                    seen_types.add(f["type"])
                    found = True
                    log_warn(logger, f"Iframe Sandbox — {f['type']} at {url}")
                    self.results.append(self._result(
                        url, f["type"], f["status"], detail=f["detail"]))

        if not found:
            log_pass(logger, f"Iframe Sandbox — no misconfigured iframes found for {url}")
            self.results.append(self._result(
                url,
                "Iframe Sandbox — no iframe sandbox misconfigurations detected",
                "PASS",
                detail="No sandbox escape, unsandboxed cross-origin iframes, or risky sandbox tokens found.",
            ))

        return self.results
