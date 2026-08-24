"""Tabnabbing — target=_blank without rel=noopener, window.opener access, reverse tabnabbing."""
import re
from .base import BaseScanner

_BLANK_LINK_RE = re.compile(
    r'<a\b[^>]*\btarget\s*=\s*["\']_blank["\'][^>]*>',
    re.I | re.S,
)
_REL_NOOPENER_RE = re.compile(r'\bnoopener\b', re.I)
_REL_NOREFERRER_RE = re.compile(r'\bnoreferrer\b', re.I)
_REL_ATTR_RE = re.compile(r'\brel\s*=\s*["\']([^"\']*)["\']', re.I)

_WINDOW_OPEN_RE = re.compile(
    r'window\.open\s*\(\s*[^,)]+(?:,[^,)]+)?\s*\)',
    re.I,
)
_OPENER_ACCESS_RE = re.compile(
    r'window\.opener\s*(?:\.|\[)',
    re.I,
)
_OPENER_NULL_RE = re.compile(
    r'window\.opener\s*=\s*null',
    re.I,
)


def _parse_blank_links(html: str) -> tuple[int, int]:
    """Return (total_blank_links, unsafe_blank_links_count)."""
    total = 0
    unsafe = 0
    for m in _BLANK_LINK_RE.finditer(html):
        tag = m.group(0)
        total += 1
        rel_m = _REL_ATTR_RE.search(tag)
        if not rel_m:
            unsafe += 1
            continue
        rel_val = rel_m.group(1)
        if not (_REL_NOOPENER_RE.search(rel_val) or _REL_NOREFERRER_RE.search(rel_val)):
            unsafe += 1
    return total, unsafe


def _check_window_open_noopener(js: str) -> list:
    """Check window.open() calls missing 'noopener' in the features string."""
    findings = []
    for m in _WINDOW_OPEN_RE.finditer(js):
        call = m.group(0)
        if "noopener" not in call.lower():
            findings.append(call[:100])
            if len(findings) >= 3:
                break
    return findings


class TabnabbingScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "tabnabbing_no_response", "PASS",
                                 detail="No response")]

        body = resp.text or ""

        total_blank, unsafe_blank = _parse_blank_links(body)
        if unsafe_blank > 0:
            sev = "FAIL" if unsafe_blank >= 3 else "WARN"
            results.append(self._result(url, "tabnabbing_blank_link_missing_noopener", sev,
                                        detail=(f"{unsafe_blank}/{total_blank} target=_blank links "
                                                f"missing rel=\"noopener noreferrer\" — "
                                                f"attacker-controlled tabs can redirect the opener page")))

        open_issues = _check_window_open_noopener(body)
        if open_issues:
            results.append(self._result(url, "tabnabbing_window_open_no_noopener", "WARN",
                                        detail=(f"window.open() calls without 'noopener' feature: "
                                                f"{open_issues[0]!r} ...")))

        if _OPENER_ACCESS_RE.search(body) and not _OPENER_NULL_RE.search(body):
            results.append(self._result(url, "tabnabbing_opener_access", "WARN",
                                        detail="window.opener property accessed without setting it to null — "
                                               "page may be vulnerable to opener control from child tab"))

        if not results:
            if total_blank > 0:
                results.append(self._result(url, "tabnabbing_protected", "PASS",
                                            detail=f"All {total_blank} target=_blank links include rel=\"noopener\""))
            else:
                results.append(self._result(url, "tabnabbing_no_blank_links", "PASS",
                                            detail="No target=_blank links found"))
        return results
