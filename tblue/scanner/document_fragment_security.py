"""Document Fragment security scanner — passive detection of DocumentFragment/Range API injection."""
import re
from .base import BaseScanner

_DF_ANY_RE = re.compile(
    r'(?:document\.createDocumentFragment\s*\(|DocumentFragment\b|'
    r'document\.createRange\s*\(|Range\b|createContextualFragment\s*\(|'
    r'range\.surroundContents\s*\(|range\.extractContents\s*\(|'
    r'range\.insertNode\s*\(|range\.cloneContents\s*\()',
    re.I,
)

_DF_FRAGMENT_FROM_PARAM_RE = re.compile(
    r'createContextualFragment\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href|innerHTML)',
    re.I,
)

_DF_INSERT_FROM_PARAM_RE = re.compile(
    r'(?:searchParams|location\.hash|location\.href)[^;]{0,400}'
    r'range\.insertNode\s*\(',
    re.I,
)

_DF_EXFIL_EXTRACTED_RE = re.compile(
    r'range\.extractContents\s*\([^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_DF_CLONE_EXFIL_RE = re.compile(
    r'range\.cloneContents\s*\([^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class DocumentFragmentSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "document_fragment_not_used", "PASS")]

        body = resp.text

        if not _DF_ANY_RE.search(body):
            return [self._result(url, "document_fragment_not_used", "PASS")]

        findings = []

        if _DF_FRAGMENT_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "document_fragment_from_param", "FAIL",
                detail="createContextualFragment() parses HTML from URL parameter/innerHTML — attacker-controlled HTML injection via Range API.",
            ))

        if _DF_INSERT_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "document_fragment_insert_from_param", "WARN",
                detail="range.insertNode() inserts content from URL parameter — attacker-controlled node insertion into DOM via Range.",
            ))

        if _DF_EXFIL_EXTRACTED_RE.search(body):
            findings.append(self._result(
                url, "document_fragment_exfil_extracted", "WARN",
                detail="range.extractContents() result transmitted via fetch/sendBeacon — DOM content exfiltrated via Range extraction.",
            ))

        if _DF_CLONE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "document_fragment_clone_exfil", "WARN",
                detail="range.cloneContents() result sent to analytics/remote — DOM subtree cloned and exfiltrated for content surveillance.",
            ))

        return findings or [self._result(url, "document_fragment_safe", "PASS")]
