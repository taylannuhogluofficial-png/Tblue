"""Content Index API security scanner — sensitive offline content indexed, content list exfiltration."""
import re
from .base import BaseScanner

_CI_ANY_RE = re.compile(
    r'(?:registration\.index\b|ContentIndex\b|index\.add\s*\(|index\.getAll\s*\(\s*\)|index\.delete\s*\()',
    re.I
)

# Content index entry derived from URL parameter — attacker adds arbitrary items to index
_CI_ADD_FROM_PARAM_RE = re.compile(
    r'index\.add\s*\([^)]*(?:searchParams|location\.search|getParam|location\.hash)',
    re.I
)

# Sensitive content indexed (auth pages, payment pages, private content)
_CI_SENSITIVE_CONTENT_RE = re.compile(
    r'index\.add\s*\([^)]*(?:password|auth|token|payment|billing|admin|private|secret)',
    re.I
)

# All indexed content enumerated and transmitted — content inventory exfiltration
_CI_ENUMERATE_EXFIL_RE = re.compile(
    r'index\.getAll\s*\(\s*\)[^;]{0,300}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I | re.S
)

# Content URLs in index transmitted — reveals which offline pages exist for this user
_CI_URL_EXFIL_RE = re.compile(
    r'index\.getAll[^;]{0,300}(?:url|id)[^;]{0,200}(?:fetch|sendBeacon|analytics)',
    re.I | re.S
)

# Content index used with external URL — indexing content from other origins
_CI_EXTERNAL_URL_RE = re.compile(
    r'index\.add\s*\([^)]*(?:url|launchUrl)\s*:\s*["\']https?://',
    re.I
)


class ContentIndexSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "content_index_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _CI_ANY_RE.search(body):
            return [self._result(url, "content_index_not_used", "INFO",
                                 detail="Content Index API not detected")]

        results = []

        if _CI_ADD_FROM_PARAM_RE.search(body):
            results.append(self._result(url, "content_index_entry_from_url_param", "WARN",
                                        detail="Content index entry derived from URL parameter — attacker adds arbitrary items to offline content index via URL manipulation"))

        if _CI_SENSITIVE_CONTENT_RE.search(body):
            results.append(self._result(url, "content_index_sensitive_content", "WARN",
                                        detail="Sensitive pages (auth/payment/admin) indexed — authentication-required pages in offline index may be accessible without auth"))

        if _CI_ENUMERATE_EXFIL_RE.search(body):
            results.append(self._result(url, "content_index_all_entries_exfiltrated", "FAIL",
                                        detail="index.getAll() result transmitted to remote — complete offline content inventory sent to analytics or remote server"))

        if _CI_URL_EXFIL_RE.search(body):
            results.append(self._result(url, "content_index_urls_exfiltrated", "WARN",
                                        detail="Indexed content URLs exfiltrated — which pages are available offline reveals user's offline content configuration"))

        if _CI_EXTERNAL_URL_RE.search(body):
            results.append(self._result(url, "content_index_external_url", "WARN",
                                        detail="Content index entry points to external/absolute URL — cross-origin content indexed in service worker offline cache"))

        if not results:
            results.append(self._result(url, "content_index_found_no_issues", "PASS",
                                        detail="Content Index API usage appears safe"))

        return results
