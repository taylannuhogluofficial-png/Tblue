"""HTTP 103 Early Hints security — resource paths exposed in Link headers, sensitive internal URLs in preload hints."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

_LINK_HEADER_RE = re.compile(r'<([^>]+)>\s*;\s*rel=["\']?preload["\']?', re.I)
_SENSITIVE_PATH_RE = re.compile(
    r'/(?:admin|internal|private|secret|api/v\d|\.env|config|backup|debug|health|metrics)',
    re.I,
)
_EXTERNAL_URL_RE = re.compile(r'^https?://', re.I)
_CREDENTIALS_IN_URL_RE = re.compile(r'https?://[^@]+:[^@]+@', re.I)

_NONCE_HINT_RE = re.compile(r'nonce=', re.I)

_EARLY_HINT_RISK_PATHS = [
    "/api/", "/graphql", "/admin", "/_next/", "/__webpack_hmr",
    "/sockjs-node/", "/hot-update.json",
]


def _get_header(headers, name: str) -> str:
    if hasattr(headers, "get"):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    if isinstance(headers, dict):
        return headers.get(name.lower(), headers.get(name, "")) or ""
    return ""


def _get_all_link_headers(headers) -> list:
    results = []
    if hasattr(headers, "items"):
        for k, v in headers.items():
            if k.lower() == "link":
                results.append(v)
    elif isinstance(headers, dict):
        for k, v in headers.items():
            if k.lower() == "link":
                results.append(v)
    return results


class HTTPEarlyHintsSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "early_hints_no_response", "PASS", detail="No response")]

        link_headers = _get_all_link_headers(resp.headers)
        parsed = urlparse(url)
        page_host = parsed.netloc

        preload_urls = []
        for link_val in link_headers:
            for m in _LINK_HEADER_RE.finditer(link_val):
                preload_urls.append(m.group(1).strip())

        if not preload_urls:
            return [self._result(url, "early_hints_no_preload", "PASS",
                                 detail="No Link: preload headers found — 103 Early Hints not used")]

        sensitive_found = []
        external_found = []
        cred_found = []

        for pu in preload_urls:
            if _CREDENTIALS_IN_URL_RE.search(pu):
                cred_found.append(pu)
            if _SENSITIVE_PATH_RE.search(pu):
                sensitive_found.append(pu)
            if _EXTERNAL_URL_RE.match(pu):
                link_host = urlparse(pu).netloc
                if link_host and link_host != page_host:
                    external_found.append(pu)

        if cred_found:
            results.append(self._result(url, "early_hints_credentials_in_url", "FAIL",
                                        detail=f"Credentials embedded in preload URL: {cred_found[0][:80]}"))

        if sensitive_found:
            sample = sensitive_found[0][:80]
            results.append(self._result(url, "early_hints_sensitive_path_disclosed", "WARN",
                                        detail=(f"Link preload hints expose {len(sensitive_found)} sensitive path(s) "
                                                f"(admin/internal/api) — attackers enumerate internal structure from "
                                                f"Link headers without loading the page: {sample}")))

        if external_found:
            sample = external_found[0][:80]
            results.append(self._result(url, "early_hints_external_preload", "WARN",
                                        detail=(f"Link preload hints reference {len(external_found)} external domain(s) — "
                                                f"third-party servers can track user visits via preload requests: {sample}")))

        if not results:
            results.append(self._result(url, "early_hints_clean", "PASS",
                                        detail=f"Found {len(preload_urls)} preload Link header(s) with no security issues"))
        return results
