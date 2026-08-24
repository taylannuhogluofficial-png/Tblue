"""
Link Security Scanner — Reverse Tabnabbing, Opener Hijacking, and Iframe Sandbox.

Modern browsers restrict window.opener by default for cross-origin navigations,
but older browsers and same-origin links still allow a newly opened tab to
navigate the opener tab (reverse tabnabbing / opener hijacking). Additionally,
iframes embedding external content without the sandbox attribute expose the
embedding site to script execution and form submission from untrusted origins.

Checks performed:
  1. Reverse Tabnabbing: <a target="_blank"> without rel="noopener"/"noreferrer"
     The opened page can set window.opener.location to redirect the parent tab.
     CWE-1022: Use of Web Link to Untrusted Target with window.opener Access
     Fixed by: rel="noopener noreferrer" on all target="_blank" links.

  2. External Iframe without sandbox: <iframe src="https://external.com"> without
     a sandbox attribute. The embedded page inherits the embedding origin's
     storage access if same-site, and can navigate the top frame.
     CWE-1021: Improper Restriction of Rendered UI Layers or Frames
     Fixed by: sandbox="allow-scripts allow-same-origin" (minimum required attrs).

  3. window.open() without 'noopener': Inline JS using window.open() without
     specifying 'noopener' in the feature string. Same risk as (1).
     Fixed by: window.open(url, '_blank', 'noopener,noreferrer')

  4. DNS-prefetch / preconnect to third-party origins: <link rel="dns-prefetch">
     or <link rel="preconnect"> pointing to external origins reveals browsing
     behavior to third parties via side channels.
     Fixed by: only prefetch necessary origins; avoid tracking domains.

All checks are passive (no probes sent to linked targets).

Professional equivalents: Detectify "Target Blank", Mozilla Observatory "Redirection",
SecurityHeaders.io "Referrer-Policy" context, Snyk "Reverse Tabnabbing".

CWE-1022: Use of Web Link to Untrusted Target with window.opener Access
CWE-1021: Improper Restriction of Rendered UI Layers or Frames
CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# --- Regex patterns ---

# Match <a ... target="_blank" ...> or target=_blank (without quotes)
_ANCHOR_RE = re.compile(
    r'<a\s[^>]*>',
    re.I | re.S,
)
_TARGET_BLANK_RE = re.compile(
    r"""target\s*=\s*(?:"_blank"|'_blank'|_blank)""",
    re.I,
)
_REL_ATTR_RE = re.compile(
    r"""rel\s*=\s*(?:"([^"]*)"|\s*'([^']*)'|([^\s>]*))""",
    re.I,
)
_HREF_ATTR_RE = re.compile(
    r"""href\s*=\s*(?:"([^"]*)"|\s*'([^']*)'|([^\s>]*))""",
    re.I,
)

# Match <iframe ... src="..." ...> elements
_IFRAME_RE = re.compile(
    r'<iframe\s[^>]*/?>',
    re.I | re.S,
)
_IFRAME_SRC_RE = re.compile(
    r"""src\s*=\s*(?:"([^"]*)"|\s*'([^']*)'|([^\s>]*))""",
    re.I,
)
_SANDBOX_ATTR_RE = re.compile(r'\bsandbox\b', re.I)

# window.open without noopener in feature string
_WINDOW_OPEN_RE = re.compile(
    r"""window\.open\s*\(\s*([^,)]+)\s*,\s*['"]_blank['"]\s*(?:,\s*['"]([^'"]*)['"]\s*)?\)""",
    re.I,
)

# <link rel="dns-prefetch"> or rel="preconnect" with href
_LINK_PREFETCH_RE = re.compile(
    r"""<link\s[^>]*rel\s*=\s*(?:"[^"]*(?:dns-prefetch|preconnect)[^"]*"|'[^']*(?:dns-prefetch|preconnect)[^']*')[^>]*/?>""",
    re.I | re.S,
)

# Well-known tracking / ad domains to flag in prefetch
_TRACKING_DOMAIN_RE = re.compile(
    r'(?:doubleclick\.net|google-analytics\.com|facebook\.com|googlesyndication\.com'
    r'|analytics\.google\.com|hotjar\.com|mixpanel\.com|segment\.io|segment\.com'
    r'|newrelic\.com|nr-data\.net|amplitude\.com)',
    re.I,
)


def _extract_attr(tag: str, pattern: re.Pattern) -> Optional[str]:
    """Extract first capture group from a regex match against the tag string."""
    m = pattern.search(tag)
    if not m:
        return None
    return m.group(1) or m.group(2) or m.group(3) or ""


def _is_external(href: str, base_host: str) -> bool:
    """Return True if href points to a different host than base_host."""
    if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
        return False
    if href.startswith("//"):
        href = "https:" + href
    try:
        p = urlparse(href)
        if not p.netloc:
            return False
        return p.netloc.lower().rstrip(".") != base_host.lower().rstrip(".")
    except Exception:
        return False


class LinkSecurityScanner(BaseScanner):
    """Check links and iframes for opener hijacking and sandbox security."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Link security — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        body = resp.text or ""
        parsed = urlparse(url)
        base_host = parsed.netloc

        self._check_target_blank_links(url, body, base_host)
        self._check_external_iframe_sandbox(url, body, base_host)
        self._check_window_open_js(url, body)
        self._check_prefetch_privacy(url, body)

        if not any(r["status"] in ("FAIL", "WARN") for r in self.results):
            log_pass(logger, f"Link security — no opener or iframe sandbox issues on {url}")
            self.results.append(self._result(
                url,
                "Link security — no opener hijacking or iframe sandbox issues found",
                "PASS",
                detail=(
                    "All target='_blank' links use rel='noopener noreferrer'. "
                    "External iframes have the sandbox attribute. "
                    "window.open() calls use the noopener feature string. "
                    "No tracking-domain prefetch directives found."
                ),
            ))

        return self.results

    def _check_target_blank_links(self, url: str, body: str, base_host: str) -> None:
        """Flag <a target="_blank"> links without rel='noopener' or rel='noreferrer'."""
        dangerous = []
        for tag in _ANCHOR_RE.findall(body):
            if not _TARGET_BLANK_RE.search(tag):
                continue
            href = _extract_attr(tag, _HREF_ATTR_RE) or ""
            rel_val = _extract_attr(tag, _REL_ATTR_RE) or ""
            rel_parts = set(rel_val.lower().split())
            # noreferrer implies noopener in modern browsers, but not universally
            has_noopener = "noopener" in rel_parts or "noreferrer" in rel_parts
            if has_noopener:
                continue
            # Internal relative links are lower risk but still flag them
            is_ext = _is_external(href, base_host)
            dangerous.append((href, is_ext))

        if not dangerous:
            return

        external_count = sum(1 for _, ext in dangerous if ext)
        total_count = len(dangerous)
        severity = "FAIL" if external_count > 0 else "WARN"

        sample_hrefs = [h for h, _ in dangerous[:5]]
        detail = (
            f"{total_count} link(s) use target='_blank' without rel='noopener noreferrer' "
            f"({external_count} pointing to external domains). "
            "The opened page can access window.opener and redirect the parent tab to a "
            "phishing page (reverse tabnabbing / opener hijacking). "
            f"Example links: {', '.join(sample_hrefs[:3])}. "
            "Fix: add rel=\"noopener noreferrer\" to all target='_blank' anchor elements. "
            "CWE-1022. Checked by Detectify, Mozilla Observatory."
        )
        if severity == "FAIL":
            log_fail(logger, f"Reverse tabnabbing risk: {external_count} external target=_blank links missing rel=noopener on {url}")
        else:
            log_warn(logger, f"Reverse tabnabbing risk: {total_count} internal target=_blank links missing rel=noopener on {url}")

        self.results.append(self._result(
            url,
            f"Link security — target='_blank' links missing rel='noopener noreferrer' (reverse tabnabbing)",
            severity,
            detail=detail,
        ))

    def _check_external_iframe_sandbox(self, url: str, body: str, base_host: str) -> None:
        """Flag external <iframe src="..."> without a sandbox attribute."""
        unsandboxed = []
        for tag in _IFRAME_RE.findall(body):
            src = _extract_attr(tag, _IFRAME_SRC_RE) or ""
            if not _is_external(src, base_host):
                continue
            if _SANDBOX_ATTR_RE.search(tag):
                continue
            unsandboxed.append(src)

        if not unsandboxed:
            return

        detail = (
            f"{len(unsandboxed)} external iframe(s) embed third-party content without a sandbox attribute: "
            f"{', '.join(unsandboxed[:3])}. "
            "Without sandbox, the embedded page can navigate the top frame, submit forms, "
            "and run scripts in the embedding context. "
            "Fix: add sandbox='allow-scripts allow-same-origin' (or the minimum required permissions) "
            "to all iframes embedding external content. "
            "CWE-1021. Checked by Detectify, OWASP."
        )
        log_fail(logger, f"External iframe without sandbox on {url}: {unsandboxed[:2]}")
        self.results.append(self._result(
            url,
            "Link security — external iframe embedded without sandbox attribute",
            "FAIL",
            detail=detail,
        ))

    def _check_window_open_js(self, url: str, body: str) -> None:
        """Flag window.open('...', '_blank') calls without 'noopener' feature string."""
        dangerous = []
        for m in _WINDOW_OPEN_RE.finditer(body):
            feature_str = (m.group(2) or "").lower()
            if "noopener" in feature_str:
                continue
            target_url = m.group(1).strip().strip("'\"")
            dangerous.append(target_url)

        if not dangerous:
            return

        detail = (
            f"{len(dangerous)} window.open() call(s) with '_blank' target lack the 'noopener' feature string. "
            f"Example: {dangerous[0][:80]}. "
            "This allows the newly opened window to access window.opener and redirect the parent. "
            "Fix: use window.open(url, '_blank', 'noopener,noreferrer'). "
            "CWE-1022."
        )
        log_warn(logger, f"window.open() without noopener on {url}")
        self.results.append(self._result(
            url,
            "Link security — window.open('_blank') without 'noopener' feature string",
            "WARN",
            detail=detail,
        ))

    def _check_prefetch_privacy(self, url: str, body: str) -> None:
        """Flag dns-prefetch/preconnect to tracking/ad domains."""
        tracking_prefetches = []
        for tag in _LINK_PREFETCH_RE.findall(body):
            href = _extract_attr(tag, _HREF_ATTR_RE) or ""
            if _TRACKING_DOMAIN_RE.search(href):
                tracking_prefetches.append(href)

        if not tracking_prefetches:
            return

        detail = (
            f"{len(tracking_prefetches)} dns-prefetch/preconnect directive(s) point to known tracking domains: "
            f"{', '.join(tracking_prefetches[:3])}. "
            "These directives cause the browser to pre-resolve DNS or establish connections "
            "to third parties before any content from those domains is loaded, leaking visit "
            "timing information. "
            "Fix: remove prefetch directives for tracking domains; consider Referrer-Policy "
            "and a strict Content-Security-Policy to limit third-party connections."
        )
        log_warn(logger, f"Tracking domain prefetch directives on {url}: {tracking_prefetches[:2]}")
        self.results.append(self._result(
            url,
            "Link security — dns-prefetch/preconnect to tracking domains",
            "WARN",
            detail=detail,
        ))
