"""Race Condition Passive scanner — passive detection of race condition vulnerability indicators."""
import re
from .base import BaseScanner

_RC_ANY_RE = re.compile(
    r'(?:balance|quantity|stock|inventory|counter|credit|token|'
    r'concurrent|transaction|idempotent|mutex|lock|'
    r'transfer|withdraw|purchase|checkout|redeem|'
    r'ETag|Last-Modified)',
    re.I,
)

_RC_NO_IDEMPOTENCY_HEADER_RE = re.compile(
    r'(?:Idempotency-Key|X-Idempotency-Key|X-Request-Id)',
    re.I,
)

_RC_FINANCIAL_OPERATION_RE = re.compile(
    r'(?:/(?:transfer|withdraw|purchase|checkout|redeem|'
    r'apply-coupon|use-voucher|spend-credit))',
    re.I,
)

_RC_COUNTER_OPERATION_RE = re.compile(
    r'(?:"(?:balance|quantity|stock|credits?|points?|tokens?)"\s*:\s*\d+|'
    r'(?:deduct|decrement|subtract|reduce)\s*(?:balance|quantity|stock))',
    re.I,
)

_RC_NO_ETAG_RE = re.compile(r'ETag\s*:', re.I)
_RC_NO_LAST_MODIFIED_RE = re.compile(r'Last-Modified\s*:', re.I)

_RC_TOCTOU_PATTERN_RE = re.compile(
    r'(?:if\s*\(\s*(?:balance|stock|quantity|credit)\s*[><=!]+|'
    r'check.*then.*update|validate.*before.*save)',
    re.I,
)

_RC_DOUBLE_SPEND_RE = re.compile(
    r'(?:coupon|voucher|promo|discount|referral)\s*(?:code|token)\s*'
    r'(?:applied|used|redeemed)',
    re.I,
)


class RaceConditionPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "race_condition_not_used", "PASS")]

        body = resp.text
        headers_str = ' '.join(f'{k}: {v}' for k, v in resp.headers.items())

        if (not _RC_ANY_RE.search(body)
                and not _RC_ANY_RE.search(headers_str)
                and not _RC_ANY_RE.search(url)):
            return [self._result(url, "race_condition_not_used", "PASS")]

        findings = []

        if _RC_FINANCIAL_OPERATION_RE.search(url):
            has_idempotency = bool(_RC_NO_IDEMPOTENCY_HEADER_RE.search(headers_str))
            if not has_idempotency:
                findings.append(self._result(
                    url, "race_condition_financial_no_idempotency", "FAIL",
                    detail="Financial operation endpoint (transfer, withdraw, purchase, checkout) without Idempotency-Key header — concurrent duplicate requests process multiple times; classic race condition enabling double-spend or double-withdrawal.",
                ))

        if _RC_COUNTER_OPERATION_RE.search(body):
            has_etag = bool(_RC_NO_ETAG_RE.search(headers_str))
            has_modified = bool(_RC_NO_LAST_MODIFIED_RE.search(headers_str))
            if not has_etag and not has_modified:
                findings.append(self._result(
                    url, "race_condition_counter_no_optimistic_lock", "WARN",
                    detail="Response includes balance/stock/credit counter but no ETag or Last-Modified headers for optimistic locking — concurrent updates overwrite each other (lost update); attacker submits multiple simultaneous requests to overdraw or oversell.",
                ))

        if _RC_TOCTOU_PATTERN_RE.search(body):
            findings.append(self._result(
                url, "race_condition_toctou_pattern", "WARN",
                detail="Time-of-Check-Time-of-Use (TOCTOU) pattern: check before update without atomic operation — a second request can pass the check between the read and the write, allowing both to proceed past a guard condition.",
            ))

        if _RC_DOUBLE_SPEND_RE.search(body):
            has_idempotency = bool(_RC_NO_IDEMPOTENCY_HEADER_RE.search(headers_str))
            if not has_idempotency:
                findings.append(self._result(
                    url, "race_condition_coupon_double_spend", "WARN",
                    detail="Coupon/voucher/promo code redemption endpoint without idempotency protection — submitting the same redemption request simultaneously in multiple threads may apply the discount multiple times before the 'used' flag is set.",
                ))

        return findings or [self._result(url, "race_condition_safe", "PASS")]
