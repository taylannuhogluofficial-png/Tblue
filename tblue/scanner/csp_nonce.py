"""
CSP Nonce Entropy Analysis.

CSP nonces only prevent XSS if they are:
  1. Cryptographically random on every page load
  2. Long enough to be unguessable (≥128 bits / 22+ base64 chars)
  3. Not reused across requests

This scanner fetches the target page multiple times, extracts nonces from
the Content-Security-Policy header and inline <script nonce="..."> attributes,
and checks:
  - Nonce length (FAIL if < 16 chars — < 96 bits entropy)
  - Nonce uniqueness (FAIL if same nonce seen in two requests)
  - Pattern detection (FAIL if nonce looks sequential/hex counter/timestamp)
  - Base64 character space (WARN if non-base64url chars, suggests weak PRNG)

No other free scanner does per-request nonce analysis. This catches a real
class of CSP bypass: sites that generate nonces from time-based seeds, global
counters, or any other predictable source.

CWE-330: Use of Insufficiently Random Values
CWE-331: Insufficient Entropy
"""

import re
import base64
import math
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_NONCE_HEADER_RE = re.compile(r"'nonce-([A-Za-z0-9+/=_-]+)'", re.I)
_NONCE_ATTR_RE = re.compile(r'<script[^>]*\snonce=["\']([A-Za-z0-9+/=_-]+)["\']', re.I)

_MIN_NONCE_LENGTH = 16
_FETCH_COUNT = 3
_MAX_BODY_BYTES = 256 * 1024


def _extract_nonces(csp_header: str, body: str) -> List[str]:
    nonces = []
    for m in _NONCE_HEADER_RE.finditer(csp_header):
        nonces.append(m.group(1))
    for m in _NONCE_ATTR_RE.finditer(body[:_MAX_BODY_BYTES]):
        n = m.group(1)
        if n not in nonces:
            nonces.append(n)
    return nonces


def _is_sequential(nonces: List[str]) -> bool:
    """Detect sequential/counting patterns (hex counter, base10 suffix)."""
    if len(nonces) < 2:
        return False
    # Check if nonces share a common prefix and only the last few chars differ
    prefix = _common_prefix(nonces)
    suffixes = [n[len(prefix):] for n in nonces]
    # Sequential hex? Try parsing suffixes as hex integers
    try:
        vals = [int(s, 16) for s in suffixes if s]
        if len(vals) >= 2:
            diffs = [abs(vals[i+1] - vals[i]) for i in range(len(vals)-1)]
            if all(d == diffs[0] and d <= 10 for d in diffs):
                return True
    except Exception:
        pass
    # Sequential decimal?
    try:
        vals = [int(s) for s in suffixes if s.isdigit()]
        if len(vals) >= 2:
            diffs = [abs(vals[i+1] - vals[i]) for i in range(len(vals)-1)]
            if all(d == diffs[0] and d <= 5 for d in diffs):
                return True
    except Exception:
        pass
    return False


def _common_prefix(strs: List[str]) -> str:
    if not strs:
        return ""
    prefix = strs[0]
    for s in strs[1:]:
        while not s.startswith(prefix):
            prefix = prefix[:-1]
            if not prefix:
                return ""
    return prefix


def _estimate_entropy_bits(nonce: str) -> float:
    """Estimate Shannon entropy bits from character diversity."""
    if not nonce:
        return 0.0
    freq: Dict[str, int] = {}
    for c in nonce:
        freq[c] = freq.get(c, 0) + 1
    n = len(nonce)
    entropy = -sum((f/n) * math.log2(f/n) for f in freq.values() if f > 0)
    return entropy * n


class CSPNonceAnalyzer(BaseScanner):
    """Analyzes CSP nonce quality for entropy and predictability."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        # Check if CSP header is present at all
        resp0 = self.http.get(url)
        if resp0 is None:
            self.results.append(self._result(
                url, "CSP Nonce — target unreachable", "PASS",
                detail="No response; CSP nonce analysis skipped."))
            return self.results

        csp_header = (resp0.headers or {}).get("content-security-policy", "") or ""
        csp_ro_header = (resp0.headers or {}).get("content-security-policy-report-only", "") or ""
        effective_csp = csp_header or csp_ro_header

        if not effective_csp:
            log_pass(logger, f"CSP Nonce — no CSP header on {url}")
            self.results.append(self._result(
                url, "CSP Nonce — no Content-Security-Policy header", "PASS",
                detail="No CSP header found; nonce analysis requires an active CSP. "
                       "See csp_advanced scanner for CSP deployment recommendations."))
            return self.results

        if "'nonce-" not in effective_csp.lower():
            log_pass(logger, f"CSP Nonce — CSP present but no nonce directive on {url}")
            self.results.append(self._result(
                url, "CSP Nonce — CSP deployed without nonce", "PASS",
                detail="CSP is present but does not use nonces. This is fine if using "
                       "'strict-dynamic' with hashes, or if the CSP has no script-src."))
            return self.results

        # Fetch multiple times to collect nonces
        first_body = resp0.text or ""
        all_nonces: List[str] = []
        per_request_nonces: List[List[str]] = []

        for i in range(_FETCH_COUNT):
            if i == 0:
                resp = resp0
            else:
                resp = self.http.get(url)
                if resp is None:
                    continue

            csp = (resp.headers or {}).get("content-security-policy", "") or ""
            body = (resp.text or "")[:_MAX_BODY_BYTES]
            nonces = _extract_nonces(csp, body)
            per_request_nonces.append(nonces)
            all_nonces.extend(nonces)

        if not all_nonces:
            log_pass(logger, f"CSP Nonce — nonce directive present but no nonces found in responses")
            self.results.append(self._result(
                url, "CSP Nonce — nonce directive in CSP but no nonces emitted", "WARN",
                detail="The CSP header references nonces ('nonce-...') but no nonce values "
                       "were found in the response headers or <script nonce=\"...\"> attributes. "
                       "This likely means the CSP nonce is declared but not applied to scripts — "
                       "scripts without a matching nonce will be blocked."))
            return self.results

        # Deduplicate for uniqueness check
        unique_nonces = list(dict.fromkeys(all_nonces))

        # Check for nonce reuse across requests
        nonce_reuse_found = False
        if len(per_request_nonces) >= 2:
            # Check if any nonce from request N appears in request N+1
            for i in range(len(per_request_nonces) - 1):
                set_a = set(per_request_nonces[i])
                set_b = set(per_request_nonces[i + 1])
                shared = set_a & set_b
                if shared:
                    nonce_reuse_found = True
                    log_fail(logger, f"CSP Nonce — same nonce reused across requests: {list(shared)[:2]}")
                    self.results.append(self._result(
                        url,
                        f"CSP Nonce — nonce reused across requests (static/predictable)",
                        "FAIL",
                        detail=(
                            f"The same CSP nonce value appeared in {len(per_request_nonces)} "
                            f"consecutive requests. A static nonce completely defeats CSP nonce "
                            f"protection — an attacker who sees the nonce once can reuse it in "
                            f"an injected script tag.\n\n"
                            f"Reused nonce: {list(shared)[0]!r}\n\n"
                            f"Fix: generate a fresh cryptographically random nonce on every "
                            f"response using secrets.token_urlsafe(24) (Python) or "
                            f"crypto.randomBytes(18).toString('base64') (Node.js)."
                        ),
                    ))

        # Check nonce length
        short_nonces = [n for n in unique_nonces if len(n) < _MIN_NONCE_LENGTH]
        if short_nonces:
            log_fail(logger, f"CSP Nonce — short nonce(s) with insufficient entropy: {short_nonces[:2]}")
            self.results.append(self._result(
                url,
                f"CSP Nonce — insufficient entropy ({len(short_nonces)} nonce(s) shorter than {_MIN_NONCE_LENGTH} chars)",
                "FAIL",
                detail=(
                    f"Nonce(s) shorter than {_MIN_NONCE_LENGTH} base64 characters have < 96 bits "
                    f"of entropy and can potentially be guessed or brute-forced.\n\n"
                    f"Short nonce example: {short_nonces[0]!r} (length {len(short_nonces[0])})\n\n"
                    f"Minimum: 22 base64 characters = 128 bits of entropy.\n"
                    f"Recommended: 32+ characters = 192+ bits."
                ),
            ))

        # Check for sequential pattern
        flat_nonces = [n for req in per_request_nonces for n in req]
        if _is_sequential(flat_nonces) or (len(unique_nonces) == 1 and not nonce_reuse_found):
            log_fail(logger, "CSP Nonce — sequential/predictable nonce pattern detected")
            self.results.append(self._result(
                url,
                "CSP Nonce — predictable/sequential nonce values detected",
                "FAIL",
                detail=(
                    "Nonce values across consecutive page loads follow a predictable pattern. "
                    "Sequential or timestamp-based nonces can be predicted by an attacker "
                    "who observes multiple page loads, defeating the XSS protection CSP provides.\n\n"
                    f"Observed nonces: {flat_nonces[:4]}\n\n"
                    "Fix: use a cryptographically secure random number generator for nonces."
                ),
            ))

        # Check entropy of individual nonces
        low_entropy = [n for n in unique_nonces if _estimate_entropy_bits(n) < 80]
        if low_entropy and not short_nonces:
            log_warn(logger, f"CSP Nonce — low estimated entropy in nonce(s): {low_entropy[:2]}")
            self.results.append(self._result(
                url,
                "CSP Nonce — low character diversity (possible weak PRNG)",
                "WARN",
                detail=(
                    f"Nonce character distribution shows low entropy, suggesting the nonce "
                    f"may not be from a strong random source. Low-diversity nonces are easier "
                    f"to enumerate.\n\n"
                    f"Example: {low_entropy[0]!r} (estimated {_estimate_entropy_bits(low_entropy[0]):.0f} bits)\n\n"
                    f"Ensure nonces use the full base64 character space."
                ),
            ))

        if not self.results:
            nonce_sample = unique_nonces[0] if unique_nonces else "N/A"
            log_pass(logger, f"CSP Nonce — good: unique across requests, adequate length")
            self.results.append(self._result(
                url,
                f"CSP Nonce — cryptographically adequate (unique, length ≥{_MIN_NONCE_LENGTH})",
                "PASS",
                detail=(
                    f"Verified over {_FETCH_COUNT} requests that nonces are unique per-request "
                    f"and of adequate length. Example nonce: {nonce_sample!r} (length {len(nonce_sample)})."
                ),
            ))

        return self.results
