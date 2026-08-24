"""Intl / Internationalization security scanner — passive detection of Intl API fingerprinting."""
import re
from .base import BaseScanner

_INTL_ANY_RE = re.compile(
    r'(?:Intl\.Collator\b|Intl\.DateTimeFormat\b|Intl\.NumberFormat\b|'
    r'Intl\.RelativeTimeFormat\b|Intl\.ListFormat\b|Intl\.Segmenter\b|'
    r'Intl\.PluralRules\b|Intl\.getCanonicalLocales\b|'
    r'navigator\.languages\b|navigator\.language\b)',
    re.I,
)

_INTL_LOCALE_FINGERPRINT_RE = re.compile(
    r'(?:navigator\.languages|navigator\.language)\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_INTL_COLLATOR_FINGERPRINT_RE = re.compile(
    r'Intl\.Collator\b[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_INTL_NUMBER_FORMAT_FINGERPRINT_RE = re.compile(
    r'Intl\.NumberFormat\b[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_INTL_FROM_PARAM_RE = re.compile(
    r'new\s+Intl\.(?:Collator|DateTimeFormat|NumberFormat|Segmenter)\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)


class IntlSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "intl_not_used", "PASS")]

        body = resp.text

        if not _INTL_ANY_RE.search(body):
            return [self._result(url, "intl_not_used", "PASS")]

        findings = []

        if _INTL_LOCALE_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "intl_locale_fingerprint", "WARN",
                detail="navigator.languages/language transmitted to remote — browser locale reveals geographic location and language preferences for fingerprinting.",
            ))

        if _INTL_COLLATOR_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "intl_collator_fingerprint", "WARN",
                detail="Intl.Collator result transmitted to analytics — locale-specific string comparison behavior used for cross-site user fingerprinting.",
            ))

        if _INTL_NUMBER_FORMAT_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "intl_number_format_fingerprint", "WARN",
                detail="Intl.NumberFormat result transmitted to analytics — locale-specific number formatting reveals user locale for fingerprinting.",
            ))

        if _INTL_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "intl_locale_from_param", "WARN",
                detail="Intl.Collator/DateTimeFormat/NumberFormat locale from URL parameter — attacker-controlled locale injection changes formatting behavior.",
            ))

        return findings or [self._result(url, "intl_safe", "PASS")]
