"""Private Aggregation API security scanner — passive detection of histogram data misuse."""
import re
from .base import BaseScanner

_PA_ANY_RE = re.compile(
    r'(?:privateAggregation\b|contributeToHistogram\s*\(|PrivateAggregation\b|enableDebugMode\s*\()',
    re.I,
)

_PA_PII_IN_BUCKET_RE = re.compile(
    r'contributeToHistogram\s*\([^)]*bucket[^)]*(?:userId|email|phone|account)[^)]*\)',
    re.I,
)

_PA_DEBUG_ENABLED_RE = re.compile(
    r'privateAggregation\b[^;]{0,100}enableDebugMode\s*\(',
    re.I,
)

_PA_BUCKET_FROM_PARAM_RE = re.compile(
    r'contributeToHistogram\s*\([^)]*(?:searchParams|location\.hash)[^)]*\)',
    re.I,
)

_PA_LARGE_VALUE_RE = re.compile(
    r'contributeToHistogram\s*\(\s*\{[^}]*value\s*:\s*(?:[1-9][0-9]{6,})',
    re.I,
)


class PrivateAggregationSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "private_aggregation_not_used", "PASS")]

        body = resp.text

        if not _PA_ANY_RE.search(body):
            return [self._result(url, "private_aggregation_not_used", "PASS")]

        findings = []

        if _PA_PII_IN_BUCKET_RE.search(body):
            findings.append(self._result(
                url, "private_aggregation_pii_in_bucket", "FAIL",
                detail="Private Aggregation bucket key encodes PII (userId/email) — user identity in aggregated histogram.",
            ))

        if _PA_DEBUG_ENABLED_RE.search(body):
            findings.append(self._result(
                url, "private_aggregation_debug_mode", "WARN",
                detail="privateAggregation.enableDebugMode() in production — bypasses aggregation noise guarantees.",
            ))

        if _PA_BUCKET_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "private_aggregation_bucket_from_param", "FAIL",
                detail="Private Aggregation bucket sourced from URL parameter — attacker-controlled histogram key.",
            ))

        return findings or [self._result(url, "private_aggregation_safe", "PASS")]
