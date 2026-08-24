"""Tabnapping Passive scanner — passive detection of window.opener and reverse tabnapping vulnerabilities."""
import re
from .base import BaseScanner

_TAB_ANY_RE = re.compile(
    r'(?:window\.open|target\s*=\s*["\']_blank["\']|'
    r'rel\s*=\s*["\']noopener|rel\s*=\s*["\']noreferrer|'
    r'window\.opener)',
    re.I,
)

_TAB_BLANK_NO_NOOPENER_RE = re.compile(
    r'<a\b[^>]*target\s*=\s*["\']_blank["\'][^>]*>'
    r'(?!(?:[^<]*<[^>]*rel\s*=\s*["\'][^"\']*noopener))',
    re.I,
)

_TAB_WINDOW_OPEN_NO_NOOPENER_RE = re.compile(
    r'window\.open\s*\([^)]{0,300}\)'
    r'(?![\s\S]{0,200}window\.opener\s*=\s*null)',
    re.I | re.S,
)

_TAB_OPENER_NOT_NULLED_RE = re.compile(
    r'window\.opener\b(?!\s*=\s*null)',
    re.I,
)

_TAB_LOCATION_VIA_OPENER_RE = re.compile(
    r'window\.opener\s*\.\s*location\s*(?:=|\.(?:href|replace))',
    re.I,
)

_TAB_POSTMESSAGE_OPENER_RE = re.compile(
    r'window\.opener\s*\.\s*postMessage\s*\(',
    re.I,
)

_TAB_REFERRER_POLICY_MISSING_RE = re.compile(
    r'(?:Referrer-Policy\s*:|referrerpolicy\s*=)',
    re.I,
)


class TabnappingPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "tabnapping_not_used", "PASS")]

        body = resp.text
        headers_str = ' '.join(f'{k}: {v}' for k, v in resp.headers.items())

        if not _TAB_ANY_RE.search(body):
            return [self._result(url, "tabnapping_not_used", "PASS")]

        findings = []

        if _TAB_BLANK_NO_NOOPENER_RE.search(body):
            findings.append(self._result(
                url, "tabnapping_blank_link_no_noopener", "WARN",
                detail='<a target="_blank"> without rel="noopener noreferrer" — the opened page receives a reference to the opener window via window.opener; malicious target page can redirect the opener to a phishing page while user is on the new tab (reverse tabnapping).',
            ))

        if _TAB_LOCATION_VIA_OPENER_RE.search(body):
            findings.append(self._result(
                url, "tabnapping_opener_location_redirect", "FAIL",
                detail="window.opener.location assignment detected — this page changes the URL of the page that opened it; attacker-controlled child page uses this to redirect a victim's browser tab to a phishing login page while they are distracted.",
            ))

        if _TAB_POSTMESSAGE_OPENER_RE.search(body):
            findings.append(self._result(
                url, "tabnapping_postmessage_to_opener", "WARN",
                detail="window.opener.postMessage() call detected — sends message to the opening window; if origin is not validated at the receiver, enables cross-origin data injection into the parent context.",
            ))

        if _TAB_WINDOW_OPEN_NO_NOOPENER_RE.search(body):
            findings.append(self._result(
                url, "tabnapping_window_open_no_null_opener", "WARN",
                detail="window.open() called without subsequently setting window.opener = null — child window retains opener reference; for user-controlled URLs this enables the opened malicious page to perform reverse tabnapping against the opener.",
            ))

        if not _TAB_REFERRER_POLICY_MISSING_RE.search(headers_str) and not _TAB_REFERRER_POLICY_MISSING_RE.search(body):
            if _TAB_BLANK_NO_NOOPENER_RE.search(body):
                findings.append(self._result(
                    url, "tabnapping_no_referrer_policy", "WARN",
                    detail="External links present without a Referrer-Policy header or referrerpolicy attribute — full URL (including path and query parameters with tokens) sent as Referer header to external sites via _blank links.",
                ))

        return findings or [self._result(url, "tabnapping_safe", "PASS")]
