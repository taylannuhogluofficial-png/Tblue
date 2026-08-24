"""document.domain security scanner — passive detection of document.domain manipulation."""
import re
from .base import BaseScanner

_DD_ANY_RE = re.compile(
    r'(?:document\.domain\s*=|document\.domain\b|DocumentDomain\b|'
    r'Origin-Agent-Cluster\b)',
    re.I,
)

_DD_DOMAIN_FROM_PARAM_RE = re.compile(
    r'document\.domain\s*=[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href|innerHTML)',
    re.I,
)

_DD_DOMAIN_RELAXATION_RE = re.compile(
    r'document\.domain\s*=\s*["\'][^"\']{3,}["\']',
    re.I,
)

_DD_EXFIL_AFTER_DOMAIN_RE = re.compile(
    r'document\.domain\s*=[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_DD_OAC_DISABLED_RE = re.compile(
    r'Origin-Agent-Cluster[^;\n]{0,50}(?:\?0|false|disabled)',
    re.I,
)


class DocumentDomainSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "document_domain_not_used", "PASS")]

        body = resp.text
        headers_str = " ".join(f"{k}: {v}" for k, v in (resp.headers or {}).items())
        combined = body + "\n" + headers_str

        if not _DD_ANY_RE.search(combined):
            return [self._result(url, "document_domain_not_used", "PASS")]

        findings = []

        if _DD_DOMAIN_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "document_domain_from_url_param", "FAIL",
                detail="document.domain set from URL parameter — attacker-controlled domain relaxation enabling cross-frame access.",
            ))

        if _DD_DOMAIN_RELAXATION_RE.search(body):
            findings.append(self._result(
                url, "document_domain_relaxed", "WARN",
                detail="document.domain set to a specific value — domain relaxation weakens same-origin isolation between subdomains.",
            ))

        if _DD_EXFIL_AFTER_DOMAIN_RE.search(body):
            findings.append(self._result(
                url, "document_domain_set_then_exfil", "FAIL",
                detail="document.domain modified then data transmitted — domain change used to widen access before exfiltration.",
            ))

        if _DD_OAC_DISABLED_RE.search(combined):
            findings.append(self._result(
                url, "origin_agent_cluster_disabled", "WARN",
                detail="Origin-Agent-Cluster disabled (?0/false) — allows document.domain mutation to remain effective.",
            ))

        return findings or [self._result(url, "document_domain_safe", "PASS")]
