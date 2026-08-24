"""Deep SRI analysis — CDN resources without integrity, weak hashes, cross-origin without SRI."""
import re
from urllib.parse import urlparse
from .base import BaseScanner

# script/link tags with src/href pointing to external domains
_EXTERNAL_SCRIPT_RE = re.compile(
    r'<script\b[^>]*\bsrc=["\'](?P<url>https?://(?!localhost|127\.0\.0\.1)[^"\']+)["\'][^>]*>',
    re.I,
)
_EXTERNAL_LINK_RE = re.compile(
    r'<link\b[^>]*\bhref=["\'](?P<url>https?://[^"\']+)["\'][^>]*>', re.I
)
_INTEGRITY_RE = re.compile(r'\bintegrity=["\'][^"\']+["\']', re.I)
_CROSSORIGIN_RE = re.compile(r'\bcrossorigin\b', re.I)

# Weak SRI hashes
_WEAK_HASH_RE = re.compile(r'\bintegrity=["\']sha1-', re.I)
_STRONG_HASH_RE = re.compile(r'\bintegrity=["\']sha(?:256|384|512)-', re.I)


def _extract_external_resources(body: str, host: str) -> list:
    resources = []
    for m in _EXTERNAL_SCRIPT_RE.finditer(body):
        tag = m.group(0)
        src = m.group("url")
        if host not in src:
            resources.append(("script", src, tag))
    for m in _EXTERNAL_LINK_RE.finditer(body):
        tag = m.group(0)
        href = m.group("url")
        # Only CSS/font links matter for SRI
        if ("stylesheet" in tag.lower() or "font" in href.lower()) and host not in href:
            resources.append(("link", href, tag))
    return resources


def _check_sri_for_resource(tag: str, resource_type: str, resource_url: str, page_url: str) -> list:
    findings = []
    has_integrity = bool(_INTEGRITY_RE.search(tag))
    has_crossorigin = bool(_CROSSORIGIN_RE.search(tag))

    if not has_integrity:
        findings.append({
            "type": f"sri_missing_{resource_type}",
            "status": "WARN",
            "url": page_url,
            "detail": f"External {resource_type} loaded without SRI: {resource_url[:80]}",
        })
    elif _WEAK_HASH_RE.search(tag):
        findings.append({
            "type": "sri_weak_hash",
            "status": "WARN",
            "url": page_url,
            "detail": f"External {resource_type} uses sha1 SRI hash (should be sha256/384/512): {resource_url[:80]}",
        })

    if has_integrity and not has_crossorigin:
        findings.append({
            "type": "sri_missing_crossorigin",
            "status": "WARN",
            "url": page_url,
            "detail": f"SRI present but crossorigin attribute missing on {resource_type}: "
                      f"{resource_url[:80]} — SRI check may be bypassed",
        })
    return findings


class SubresourceIntegrityDeepScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "sri_deep_no_response", "PASS",
                                 detail="No response")]

        parsed = urlparse(url)
        host = parsed.netloc
        resources = _extract_external_resources(resp.text, host)

        for resource_type, resource_url, tag in resources:
            for f in _check_sri_for_resource(tag, resource_type, resource_url, url):
                results.append(self._result(f["url"], f["type"], f["status"],
                                            detail=f["detail"]))

        if not results:
            results.append(self._result(url, "sri_deep_clean", "PASS",
                                        detail="All external resources have valid SRI attributes "
                                               "or no external resources found"))
        return results
