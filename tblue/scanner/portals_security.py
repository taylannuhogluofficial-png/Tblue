"""Portals API security scanner — HTMLPortalElement cross-origin embedding and activation security."""
import re
from .base import BaseScanner

_PORTAL_ELEM_RE  = re.compile(r'HTMLPortalElement\b|document\.createElement\s*\(\s*["\']portal["\']', re.I)
_PORTAL_TAG_RE   = re.compile(r'<portal\b', re.I)
_PORTAL_ANY_RE   = re.compile(r'(?:HTMLPortalElement\b|<portal\b|\.activate\s*\(\s*\{)', re.I)

# Portal loading sensitive internal page
_PORTAL_SENSITIVE_SRC_RE = re.compile(
    r'<portal[^>]*src\s*=\s*["\'][^"\']*(?:admin|internal|dashboard|settings|account)[^"\']*["\']',
    re.I | re.S
)

# Portal src from URL parameter — SSRF/open redirect
_PORTAL_SRC_URL_PARAM_RE = re.compile(
    r'(?:portal\.src|setAttribute\s*\(\s*["\']src["\'])[^;]{0,100}'
    r'(?:location\.|searchParams|getParam)',
    re.I | re.S
)

# Portal activate passes data to navigated page
_PORTAL_ACTIVATE_DATA_RE = re.compile(
    r'\.activate\s*\(\s*\{[^}]*data\s*:[^}]*(?:token|auth|secret|cookie|session)',
    re.I | re.S
)

# Portal message handler without origin check
_PORTAL_MSG_NO_ORIGIN_RE = re.compile(
    r'(?:onmessage|addEventListener\s*\(\s*["\']message["\'])[^;]{0,300}portal',
    re.I | re.S
)
_PORTAL_ORIGIN_CHECK_RE = re.compile(r'event\.origin\b', re.I)

# Auto-activate portal (navigates without user interaction)
_PORTAL_AUTO_ACTIVATE_RE = re.compile(
    r'(?:DOMContentLoaded|window\.onload)[^;]{0,400}\.activate\s*\(',
    re.I | re.S
)


class PortalsSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "portals_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _PORTAL_ANY_RE.search(body):
            return [self._result(url, "portals_not_used", "INFO",
                                 detail="Portals API not detected")]

        results = []

        if _PORTAL_SRC_URL_PARAM_RE.search(body):
            results.append(self._result(url, "portals_src_from_url_param", "FAIL",
                                        detail="Portal src set from URL parameter — SSRF / open redirect via portal navigation"))

        if _PORTAL_SENSITIVE_SRC_RE.search(body):
            results.append(self._result(url, "portals_sensitive_page_embedded", "WARN",
                                        detail="Portal embeds sensitive internal page — admin/dashboard visible in portal context"))

        if _PORTAL_ACTIVATE_DATA_RE.search(body):
            results.append(self._result(url, "portals_sensitive_data_on_activate", "FAIL",
                                        detail="Portal activate() passes auth/token/session data to navigated page"))

        if _PORTAL_AUTO_ACTIVATE_RE.search(body):
            results.append(self._result(url, "portals_auto_activate", "WARN",
                                        detail="Portal activated on page load — navigation without user gesture"))

        if _PORTAL_MSG_NO_ORIGIN_RE.search(body) and not _PORTAL_ORIGIN_CHECK_RE.search(body):
            results.append(self._result(url, "portals_message_no_origin_check", "WARN",
                                        detail="Portal message handler without event.origin check — cross-origin message injection"))

        if not results:
            results.append(self._result(url, "portals_found_no_issues", "PASS",
                                        detail="Portals API usage appears safe"))

        return results
