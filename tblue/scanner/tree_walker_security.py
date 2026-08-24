"""TreeWalker / NodeIterator security scanner — passive detection of DOM traversal surveillance."""
import re
from .base import BaseScanner

_TW_ANY_RE = re.compile(
    r'(?:document\.createTreeWalker\s*\(|document\.createNodeIterator\s*\(|'
    r'TreeWalker\b|NodeIterator\b|NodeFilter\b|treeWalker\.nextNode\s*\(|'
    r'treeWalker\.currentNode\b|nodeIterator\.nextNode\s*\()',
    re.I,
)

_TW_SENSITIVE_NODE_HARVEST_RE = re.compile(
    r'createTreeWalker\s*\([^;]{0,400}'
    r'(?:password|auth|token|credential|ssn|credit)',
    re.I,
)

_TW_EXFIL_TEXT_NODES_RE = re.compile(
    r'(?:treeWalker|nodeIterator)\.nextNode\s*\([^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_TW_FULL_DOCUMENT_WALK_RE = re.compile(
    r'createTreeWalker\s*\(\s*document(?:\.body|\.documentElement)?\s*,'
    r'[^)]{0,200}SHOW_ALL\b',
    re.I,
)

_TW_FROM_PARAM_RE = re.compile(
    r'createTreeWalker\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class TreeWalkerSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "tree_walker_not_used", "PASS")]

        body = resp.text

        if not _TW_ANY_RE.search(body):
            return [self._result(url, "tree_walker_not_used", "PASS")]

        findings = []

        if _TW_SENSITIVE_NODE_HARVEST_RE.search(body):
            findings.append(self._result(
                url, "tree_walker_sensitive_node_harvest", "WARN",
                detail="createTreeWalker() filtering for password/auth/credential nodes — DOM traversal targets sensitive elements for content extraction.",
            ))

        if _TW_EXFIL_TEXT_NODES_RE.search(body):
            findings.append(self._result(
                url, "tree_walker_exfil_text_nodes", "FAIL",
                detail="TreeWalker/NodeIterator nextNode() result transmitted via fetch/analytics — DOM text content exfiltrated via tree traversal.",
            ))

        if _TW_FULL_DOCUMENT_WALK_RE.search(body):
            findings.append(self._result(
                url, "tree_walker_full_document_walk", "WARN",
                detail="createTreeWalker() on document with NodeFilter.SHOW_ALL — full DOM tree traversal surveillance captures all nodes.",
            ))

        if _TW_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "tree_walker_from_param", "WARN",
                detail="createTreeWalker() parameters sourced from URL — attacker-controlled DOM traversal filter and root.",
            ))

        return findings or [self._result(url, "tree_walker_safe", "PASS")]
