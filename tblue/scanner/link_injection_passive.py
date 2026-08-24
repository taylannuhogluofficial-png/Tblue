"""Link Injection Passive scanner — passive detection of link injection and header-based redirect indicators."""
import re
from .base import BaseScanner

_LI_ANY_RE = re.compile(
    r'(?:<a\s+href|<link\s+rel|<base\s+href|'
    r'Location\s*:|Refresh\s*:|Link\s*:|'
    r'window\.location|document\.write)',
    re.I,
)

_LI_REFLECTED_URL_IN_HREF_RE = re.compile(
    r'<a\s[^>]*href\s*=\s*["\'][^"\']{0,200}'
    r'(?:searchParams|location\.hash|userInput|req\.query)',
    re.I,
)

_LI_BASE_TAG_INJECTION_RE = re.compile(
    r'<base\s[^>]*href\s*=\s*["\']https?://(?!(?:www\.)?[a-z0-9.-]+\.[a-z]{2,}["\'])[^"\']{1,200}["\']',
    re.I,
)

_LI_HEADER_INJECTION_RE = re.compile(
    r'(?:Location|Refresh|Link)\s*:[^\r\n]*'
    r'(?:searchParams|userInput|req\.query|req\.params)',
    re.I,
)

_LI_DOCUMENT_WRITE_URL_RE = re.compile(
    r'document\.write\s*\([^)]{0,200}'
    r'(?:searchParams|location\.hash|location\.search)',
    re.I,
)

_LI_OPEN_REDIRECT_HEADER_RE = re.compile(
    r'Location\s*:\s*https?://(?!(?:www\.)?[a-z0-9.-]{3,50}\.[a-z]{2,6}(?:[/?#]|$))',
    re.I,
)

_LI_WINDOW_LOCATION_PARAM_RE = re.compile(
    r'window\.location(?:\.href)?\s*=\s*[^;]{0,200}'
    r'(?:searchParams|location\.hash|req\.query)',
    re.I,
)


class LinkInjectionPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "link_injection_not_used", "PASS")]

        body = resp.text
        headers_str = ' '.join(f'{k}: {v}' for k, v in resp.headers.items())

        if not _LI_ANY_RE.search(body) and not _LI_ANY_RE.search(headers_str):
            return [self._result(url, "link_injection_not_used", "PASS")]

        findings = []

        if _LI_REFLECTED_URL_IN_HREF_RE.search(body):
            findings.append(self._result(
                url, "link_injection_href_from_param", "FAIL",
                detail="<a href> attribute value contains URL parameter reference — attacker injects javascript: or data: URL to create XSS links, or external URLs for phishing; also enables open redirect via crafted href values.",
            ))

        if _LI_DOCUMENT_WRITE_URL_RE.search(body):
            findings.append(self._result(
                url, "link_injection_document_write_from_param", "FAIL",
                detail="document.write() called with URL parameter or location.hash — writes attacker-controlled HTML into document; same impact as reflected XSS but bypasses innerHTML sinks that filter script tags.",
            ))

        if _LI_HEADER_INJECTION_RE.search(body):
            findings.append(self._result(
                url, "link_injection_response_header_from_param", "FAIL",
                detail="Location, Refresh, or Link header value contains URL parameter — HTTP response header injection; attacker adds CRLF sequences to inject arbitrary headers, split responses, or redirect to malicious sites.",
            ))

        if _LI_WINDOW_LOCATION_PARAM_RE.search(body):
            findings.append(self._result(
                url, "link_injection_window_location_from_param", "WARN",
                detail="window.location set from URL parameter — open redirect; attacker crafts URL to redirect victims to phishing page after completing a legitimate action (login, payment confirmation).",
            ))

        if _LI_BASE_TAG_INJECTION_RE.search(body):
            findings.append(self._result(
                url, "link_injection_base_tag", "WARN",
                detail="<base href> pointing to external or suspicious URL — base tag hijacking changes the base URL for all relative links; attacker-injected base tag redirects all resource loads and navigation to attacker-controlled domain.",
            ))

        return findings or [self._result(url, "link_injection_safe", "PASS")]
