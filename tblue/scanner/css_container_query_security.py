"""CSS Container Queries security scanner — passive detection of container query injection attacks."""
import re
from .base import BaseScanner

_CQ_ANY_RE = re.compile(
    r'(?:@container\b|container-type\s*:|container-name\s*:|ContainerQuery\b|'
    r'CSS\.supports\s*\(\s*["\']container|matchMedia\s*\(\s*["\']container)',
    re.I,
)

_CQ_NAME_FROM_PARAM_RE = re.compile(
    r'(?:container-name|@container)[^;{]{0,200}'
    r'(?:searchParams|location\.hash|innerHTML|document\.write)',
    re.I,
)

_CQ_INJECT_RULE_RE = re.compile(
    r'(?:insertRule|addRule|innerHTML|document\.write)[^;]{0,200}@container\b',
    re.I,
)

_CQ_STYLE_QUERY_EXFIL_RE = re.compile(
    r'@container\b[^{;]{0,100}\{[^}]{0,300}'
    r'(?:content\s*:\s*["\']https?://|url\s*\(\s*["\']https?://)',
    re.I,
)

_CQ_SIZE_FINGERPRINT_RE = re.compile(
    r'@container\b[^{;]{0,100}\([^)]*(?:min-width|max-width|min-height|max-height)[^)]*\)'
    r'[^;]{0,300}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class CSSContainerQuerySecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "css_container_query_not_used", "PASS")]

        body = resp.text

        if not _CQ_ANY_RE.search(body):
            return [self._result(url, "css_container_query_not_used", "PASS")]

        findings = []

        if _CQ_NAME_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "css_container_query_name_from_param", "FAIL",
                detail="CSS container-name or @container rule sourced from URL parameter — attacker-controlled container query injection.",
            ))

        if _CQ_INJECT_RULE_RE.search(body):
            findings.append(self._result(
                url, "css_container_query_injected", "WARN",
                detail="@container rule injected via insertRule/innerHTML — dynamic container query manipulation.",
            ))

        if _CQ_STYLE_QUERY_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "css_container_query_style_exfil", "FAIL",
                detail="@container rule applies content:url() pointing to external domain — CSS container-based exfiltration request.",
            ))

        if _CQ_SIZE_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "css_container_query_size_fingerprinting", "WARN",
                detail="Container query breakpoint triggers network request — container size used for viewport fingerprinting.",
            ))

        return findings or [self._result(url, "css_container_query_safe", "PASS")]
