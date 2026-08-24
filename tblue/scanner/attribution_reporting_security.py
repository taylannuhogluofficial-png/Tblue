"""Attribution Reporting API security scanner — passive detection of ad-tracking misuse."""
import re
from .base import BaseScanner

_AR_ANY_RE = re.compile(
    r'(?:attributionsrc\b|Attribution-Reporting\b|registerSource\b|registerTrigger\b|attributionDestination\b)',
    re.I,
)

_AR_PII_IN_SOURCE_RE = re.compile(
    r'(?:registerSource|attributionsrc)[^;]{0,300}(?:email|userId|phone|name|ssn)',
    re.I,
)

_AR_CROSS_ORIGIN_DEST_RE = re.compile(
    r'attributionDestination["\']?\s*:[^;]{0,100}["\']https?://(?!(?:localhost|127\.0\.0\.1))',
    re.I,
)

_AR_FILTER_DATA_EXFIL_RE = re.compile(
    r'filterData\s*:[^;]{0,200}(?:userId|email|phone|account)',
    re.I,
)

_AR_HIGH_PRIORITY_RE = re.compile(
    r'(?:sourcePriority|priority)\s*:\s*(?:[1-9][0-9]{5,}|[1-9][0-9]{6,})',
    re.I,
)


class AttributionReportingSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "attribution_reporting_not_used", "PASS")]

        body = resp.text

        if not _AR_ANY_RE.search(body):
            return [self._result(url, "attribution_reporting_not_used", "PASS")]

        findings = []

        if _AR_PII_IN_SOURCE_RE.search(body):
            findings.append(self._result(
                url, "attribution_source_contains_pii", "FAIL",
                detail="Attribution Reporting source registration includes PII (email/userId/phone) — user identity in ad tracking.",
            ))

        if _AR_CROSS_ORIGIN_DEST_RE.search(body):
            findings.append(self._result(
                url, "attribution_cross_origin_destination", "WARN",
                detail="Attribution destination points to external origin — cross-site conversion data sent to third party.",
            ))

        if _AR_FILTER_DATA_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "attribution_filter_data_contains_pii", "FAIL",
                detail="Attribution filterData contains PII (userId/email) — user identification embedded in ad attribution.",
            ))

        return findings or [self._result(url, "attribution_reporting_safe", "PASS")]
