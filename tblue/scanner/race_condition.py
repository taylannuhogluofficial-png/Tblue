"""
Race Condition / TOCTOU Vulnerability Scanner.

Race conditions (Time-of-Check-to-Time-of-Use flaws) occur when security
checks and resource usage happen at different times, allowing concurrent
requests to bypass limits or double-spend resources.

Common attack scenarios:
- Double-spend: redeem a gift card / coupon twice simultaneously
- Balance bypass: withdraw more funds than the balance allows
- Rate limit bypass: make N simultaneous requests to bypass per-request limits
- Account creation race: create duplicate accounts for the same email
- Token invalidation race: use a single-use token multiple times concurrently

Blue-team detection approach (strictly read-only, passive analysis):
1. Identify potentially race-vulnerable endpoints from page structure:
   - Token redemption forms (gift cards, coupons, promo codes)
   - Balance/credit operations with numeric amounts
   - Single-use token submission forms
   - Purchase/checkout endpoints
2. Check for idempotency key support (X-Idempotency-Key, Idempotency-Key headers)
3. Check for rate limit enforcement indicators
4. Detect lack of TOCTOU mitigation patterns in API responses
5. Check for atomic operation indicators (ETag-based conditional updates)

NOTE: This scanner performs NO concurrent requests — it is purely passive
analysis of endpoint structure and response characteristics.

Professional equivalent: Burp Suite Pro "Race conditions" (2023 edition)
using the single-packet attack, Turbo Intruder, James Kettle's research.

CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization
CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
OWASP API Security: API4:2023 Unrestricted Resource Consumption
"""

import re
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

# Idempotency key header names
_IDEMPOTENCY_HEADERS = frozenset({
    "idempotency-key",
    "x-idempotency-key",
    "idempotency_key",
    "x-request-id",
    "x-correlation-id",
})

# Endpoints with high TOCTOU risk (token/balance/limit operations)
_HIGH_RISK_PATHS = re.compile(
    r"""
    /(?:
        redeem|apply|use|claim|activate|validate|consume |  # token redemption
        checkout|purchase|buy|order|pay|payment |            # financial operations
        withdraw|transfer|send|debit |                       # balance operations
        vote|like|subscribe|register                         # rate-limited ops
    )(?:/|$|\?)
    """,
    re.I | re.X,
)

# Input field names suggesting single-use token redemption
_COUPON_FIELD_RE = re.compile(
    r"""
    name=["\']?(
        coupon|promo|voucher|code|gift_card|gift.card|redeem|
        discount_code|promo_code|voucher_code|token|referral_code
    )["\']?
    """,
    re.I | re.X,
)

# Numeric amount/balance field names
_AMOUNT_FIELD_RE = re.compile(
    r"""
    name=["\']?(
        amount|quantity|qty|count|balance|credit|points|
        units|shares|tokens|limit|value
    )["\']?
    """,
    re.I | re.X,
)

# Response patterns indicating non-atomic operations (TOCTOU indicators)
_NON_ATOMIC_RE = re.compile(
    r"""
    (?:checking|verifying|validating)\s+(?:balance|credits?|tokens?|codes?) |
    (?:first\s+check|then\s+(?:deduct|update|apply)) |
    if.*valid.*then.*apply |
    balance.*sufficient.*proceed
    """,
    re.I | re.X,
)

# Concurrency protection indicators (good — these reduce TOCTOU risk)
_CONCURRENCY_PROTECTED_RE = re.compile(
    r"""
    etag|if.match|if.none.match |    # ETag-based conditional updates
    optimistic.*lock|pessimistic.*lock|
    compare.and.swap|atomic |
    idempotent|idempotency
    """,
    re.I | re.X,
)

# Rate limit response indicators
_RATE_LIMIT_RE = re.compile(
    r"x-ratelimit|x-rate-limit|retry-after|x-retry-after",
    re.I,
)


class RaceConditionScanner(BaseScanner):
    """Detect endpoints structurally vulnerable to race condition / TOCTOU attacks."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            self.results.append(self._result(
                url, "Race condition — target unreachable", "PASS",
                detail="No response from target."
            ))
            return self.results

        body = resp.text or ""
        soup = BeautifulSoup(body, "html.parser")
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        found_any = False

        # ── 1. Check current URL for high-risk path ───────────────────────────
        if _HIGH_RISK_PATHS.search(url):
            found_any |= self._analyze_high_risk_endpoint(url, resp, soup)

        # ── 2. Discover high-risk endpoints from page links/forms ─────────────
        found_any |= self._discover_risky_endpoints(soup, base, url)

        # ── 3. Check API response headers for idempotency support ─────────────
        self._check_idempotency_headers(url, resp)

        if not found_any:
            log_pass(logger, f"No race condition risk indicators found on {url}")
            self.results.append(self._result(
                url,
                "Race condition — no TOCTOU-vulnerable endpoints detected",
                "PASS",
                detail=(
                    "No race-condition-vulnerable patterns detected. "
                    "Best practice: use database-level atomic operations for "
                    "balance/token operations; implement idempotency keys on all "
                    "state-changing API endpoints; use SELECT...FOR UPDATE or "
                    "optimistic locking patterns."
                )
            ))

        return self.results

    def _analyze_high_risk_endpoint(self, endpoint_url: str,
                                     resp: Any, soup: BeautifulSoup) -> bool:
        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        body = resp.text or ""

        # Check for idempotency key support in response headers
        has_idempotency = any(h in headers for h in _IDEMPOTENCY_HEADERS)
        has_etag = "etag" in headers
        has_rate_limit = bool(_RATE_LIMIT_RE.search(" ".join(headers.keys())))
        has_concurrency_protection = bool(_CONCURRENCY_PROTECTED_RE.search(body))

        form_html = str(soup)
        has_coupon_field = bool(_COUPON_FIELD_RE.search(form_html))
        has_amount_field = bool(_AMOUNT_FIELD_RE.search(form_html))

        if has_coupon_field or has_amount_field:
            if not has_idempotency and not has_etag:
                severity = "FAIL" if has_coupon_field else "WARN"
                field_type = "token/coupon redemption" if has_coupon_field else "numeric amount"
                if severity == "FAIL":
                    log_fail(logger,
                             f"Race condition risk: {field_type} endpoint without idempotency: {endpoint_url}")
                    self.results.append(self._result(
                        endpoint_url,
                        f"Race condition — {field_type} endpoint lacks idempotency protection",
                        "FAIL",
                        detail=(
                            f"The endpoint {endpoint_url} processes {field_type} operations "
                            "without idempotency key support. "
                            "Attackers can send multiple simultaneous requests to redeem a "
                            "single-use token multiple times (double-spend attack). "
                            "This is exploitable with Burp Suite Pro's single-packet attack. "
                            "Fix: implement idempotency keys (require Idempotency-Key header); "
                            "use atomic database operations (UPDATE ... WHERE used=false); "
                            "use distributed locking (Redis SETNX) for critical sections."
                        )
                    ))
                else:
                    log_warn(logger,
                             f"Race condition risk: {field_type} endpoint, check for atomic ops: {endpoint_url}")
                    self.results.append(self._result(
                        endpoint_url,
                        f"Race condition — {field_type} endpoint, verify atomic operations",
                        "WARN",
                        detail=(
                            f"The endpoint {endpoint_url} processes {field_type} operations. "
                            "Without atomic database operations and idempotency keys, "
                            "concurrent requests may bypass quantity/balance checks. "
                            "Fix: use SELECT...FOR UPDATE or optimistic locking; "
                            "add Idempotency-Key support to prevent duplicate processing."
                        )
                    ))
                return True

            elif has_idempotency or has_etag:
                protection = "Idempotency-Key" if has_idempotency else "ETag"
                log_pass(logger, f"Token redemption endpoint has {protection}: {endpoint_url}")
                self.results.append(self._result(
                    endpoint_url,
                    f"Race condition — {protection} protection present on token/amount endpoint",
                    "PASS",
                    detail=(
                        f"The endpoint uses {protection} for idempotency. "
                        "This mitigates concurrent duplicate request attacks."
                    )
                ))
                return True

        elif _HIGH_RISK_PATHS.search(endpoint_url):
            if not has_rate_limit and not has_idempotency and not has_concurrency_protection:
                log_warn(logger, f"High-risk endpoint lacks concurrency protection: {endpoint_url}")
                self.results.append(self._result(
                    endpoint_url,
                    "Race condition — high-risk endpoint lacks rate limiting or idempotency",
                    "WARN",
                    detail=(
                        f"The high-risk endpoint {endpoint_url} "
                        "(matches checkout/payment/vote/subscribe pattern) "
                        "does not include idempotency keys, ETag headers, or rate limiting. "
                        "Concurrent requests may trigger duplicate operations. "
                        "Fix: add Idempotency-Key support; implement rate limiting "
                        "(Retry-After header); use atomic database operations."
                    )
                ))
                return True

        return False

    def _discover_risky_endpoints(self, soup: BeautifulSoup,
                                   base: str, url: str) -> bool:
        found = False
        seen_paths: Set[str] = set()

        # Check all forms with POST method for high-risk actions
        for form in soup.find_all("form"):
            method = form.get("method", "get").lower()
            action = form.get("action", "")
            if not action:
                continue

            action_url = urljoin(base, action)
            action_path = urlparse(action_url).path

            if action_path in seen_paths:
                continue

            form_html = str(form)
            has_coupon = bool(_COUPON_FIELD_RE.search(form_html))
            has_amount = bool(_AMOUNT_FIELD_RE.search(form_html))
            is_high_risk_path = bool(_HIGH_RISK_PATHS.search(action_path))

            if not (has_coupon or has_amount or is_high_risk_path):
                continue

            seen_paths.add(action_path)

            # Probe the action endpoint for idempotency headers
            probe_resp = None
            try:
                probe_resp = self.http.get(action_url)
            except Exception:
                pass

            if has_coupon:
                # Check if the endpoint has idempotency protection
                has_idempotency = False
                has_etag = False
                if probe_resp:
                    probe_headers = {k.lower(): v for k, v in (probe_resp.headers or {}).items()}
                    has_idempotency = any(h in probe_headers for h in _IDEMPOTENCY_HEADERS)
                    has_etag = "etag" in probe_headers

                if not has_idempotency and not has_etag:
                    log_fail(logger,
                             f"Race condition risk: coupon/token field → {action_url} lacks idempotency")
                    self.results.append(self._result(
                        action_url,
                        "Race condition — token/coupon redemption endpoint lacks idempotency",
                        "FAIL",
                        detail=(
                            f"A form with coupon/voucher/token field posts to {action_url} "
                            "which lacks idempotency key support. "
                            "Concurrent requests can redeem a single-use token multiple times. "
                            "Fix: implement Idempotency-Key header support; "
                            "use atomic database updates (UPDATE...WHERE redeemed=false); "
                            "use distributed locking (Redis SETNX) for token redemption."
                        )
                    ))
                    found = True
                else:
                    protection = "Idempotency-Key" if has_idempotency else "ETag"
                    log_pass(logger, f"Token redemption endpoint has {protection}: {action_url}")
                    self.results.append(self._result(
                        action_url,
                        f"Race condition — {protection} protection on token redemption endpoint",
                        "PASS",
                        detail=f"Token/coupon endpoint uses {protection} — reduces double-spend risk."
                    ))
                    found = True

            elif has_amount:
                has_idempotency = False
                has_etag = False
                if probe_resp:
                    probe_headers = {k.lower(): v for k, v in (probe_resp.headers or {}).items()}
                    has_idempotency = any(h in probe_headers for h in _IDEMPOTENCY_HEADERS)
                    has_etag = "etag" in probe_headers

                if not has_idempotency and not has_etag:
                    log_warn(logger, f"Amount/balance form → {action_url}, verify atomic ops")
                    self.results.append(self._result(
                        action_url,
                        "Race condition — numeric amount endpoint, verify atomic operations",
                        "WARN",
                        detail=(
                            f"A form with amount/quantity/balance field posts to {action_url}. "
                            "Without atomic database operations, concurrent requests may bypass "
                            "balance checks. Fix: use SELECT...FOR UPDATE; add Idempotency-Key."
                        )
                    ))
                    found = True

            elif is_high_risk_path and method == "post":
                has_rate_limit = False
                has_idempotency = False
                if probe_resp:
                    probe_headers = {k.lower(): v for k, v in (probe_resp.headers or {}).items()}
                    has_rate_limit = bool(_RATE_LIMIT_RE.search(" ".join(probe_headers.keys())))
                    has_idempotency = any(h in probe_headers for h in _IDEMPOTENCY_HEADERS)

                if not has_rate_limit and not has_idempotency:
                    log_warn(logger, f"High-risk POST endpoint, no rate limit/idempotency: {action_url}")
                    self.results.append(self._result(
                        action_url,
                        "Race condition — high-risk POST endpoint lacks rate limiting or idempotency",
                        "WARN",
                        detail=(
                            f"The high-risk endpoint {action_url} lacks both rate limiting "
                            "and idempotency keys. Fix: add Idempotency-Key support; "
                            "implement rate limiting with Retry-After headers."
                        )
                    ))
                    found = True

        # Check API links for high-risk paths
        for tag in soup.find_all(["a", "link"]):
            href = tag.get("href", "")
            if not href or not _HIGH_RISK_PATHS.search(href):
                continue
            full_url = urljoin(base, href)
            path = urlparse(full_url).path
            if path in seen_paths:
                continue
            seen_paths.add(path)
            try:
                probe_resp = self.http.get(full_url)
                if probe_resp:
                    found |= self._analyze_high_risk_endpoint(
                        full_url, probe_resp,
                        BeautifulSoup(probe_resp.text or "", "html.parser")
                    )
            except Exception:
                continue

        return found

    def _check_idempotency_headers(self, url: str, resp: Any) -> None:
        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}

        # Check if this is a JSON API endpoint that should support idempotency
        content_type = headers.get("content-type", "")
        if "application/json" not in content_type:
            return

        has_idempotency = any(h in headers for h in _IDEMPOTENCY_HEADERS)
        if has_idempotency:
            log_pass(logger, f"API endpoint supports idempotency keys: {url}")
            self.results.append(self._result(
                url,
                "Race condition — idempotency key header supported on API",
                "PASS",
                detail=(
                    "The API endpoint includes idempotency key support, "
                    "protecting against duplicate concurrent request attacks."
                )
            ))
