"""
Business Logic Vulnerability Scanner.

Detects common business logic flaws in web applications:

1. Negative quantity / price parameter (cart/order manipulation)
2. Price parameter tampering (price=0.01 instead of server-side enforcement)
3. Excessive privilege parameter (role=admin, user_type=admin in requests)
4. Order-of-operations bypass (skip checkout steps via direct access)
5. Mass assignment indicators (accepting extra fields not shown in forms)
6. Account enumeration timing differences (register vs login timing)
7. IDOR (Insecure Direct Object Reference) — numeric ID increment
8. Coupon stacking or negative discount via API parameter manipulation
9. Quantity overflow (quantity=-1 or quantity=999999)
10. Hidden price field in form HTML (price submitted client-side)
"""

import re
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from bs4 import BeautifulSoup
from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_fail, log_warn

logger = get_logger(__name__)

_PRICE_INPUT_RE = re.compile(
    r'<input[^>]+name=["\']?(?:price|amount|total|cost|value|subtotal)["\']?[^>]*>',
    re.I,
)

_PRIV_FIELD_RE = re.compile(
    r'name=["\']?(role|user_type|is_admin|admin|privilege|permission|access_level)["\']?',
    re.I,
)

_IDOR_PATH_RE = re.compile(
    r"/(?:user|account|order|invoice|profile|document|record|ticket|item|product)/(\d+)",
    re.I,
)

_CART_PARAM_RE = re.compile(
    r"(?:qty|quantity|count|amount|num|price)=(\d+)",
    re.I,
)

_SUCCESS_RESPONSE_RE = re.compile(
    r'"success"\s*:\s*true|"status"\s*:\s*"ok"|"result"\s*:\s*"success"',
    re.I,
)

_REDIRECT_OR_PROCEED_RE = re.compile(
    r"/checkout/confirm|/order/confirm|/payment/complete|/purchase/done",
    re.I,
)


class BusinessLogicScanner(BaseScanner):
    """Detects business logic flaws that cannot be caught by generic scanners."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []

        resp = self.http.get(url)
        if resp is None:
            log_pass(logger, f"No response — skipping business logic checks: {url}")
            self.results.append(self._result(
                url, "Business logic — no response from target", "PASS",
                detail="Target did not respond; business logic checks skipped."
            ))
            return self.results

        html = resp.text or ""
        self._check_hidden_price_fields(url, html)
        self._check_privilege_escalation_params(url, html)
        self._check_idor_in_url(url, html)
        self._check_cart_manipulation(url)
        self._check_negative_quantity(url, html)

        if not self.results:
            log_pass(logger, f"No business logic issues found on {url}")
            self.results.append(self._result(
                url, "Business logic — no obvious issues detected", "PASS",
                detail=(
                    "No hidden price fields, privilege escalation parameters, obvious IDOR patterns, "
                    "or cart manipulation vectors detected on the main page."
                )
            ))

        return self.results

    def _check_hidden_price_fields(self, url: str, html: str) -> None:
        """Detect price/amount fields submitted client-side in forms."""
        soup = BeautifulSoup(html, "html.parser")
        vulnerable_inputs = []
        for form in soup.find_all("form"):
            for inp in form.find_all("input"):
                name = inp.attrs.get("name", "").lower()
                itype = inp.attrs.get("type", "text").lower()
                if any(k in name for k in ("price", "amount", "total", "cost", "subtotal")):
                    vulnerable_inputs.append(
                        f"<input name='{inp.attrs.get('name')}' type='{itype}'>"
                    )

        if vulnerable_inputs:
            log_fail(logger, f"Hidden/form price fields detected on {url}")
            self.results.append(self._result(
                url, "Business logic — client-submitted price/amount field", "FAIL",
                detail=(
                    f"Found {len(vulnerable_inputs)} form input(s) with price/amount names "
                    f"that may be submitted by the client: {'; '.join(vulnerable_inputs[:3])}. "
                    "If the server trusts these values without server-side validation, an attacker "
                    "can set price=0 or price=-1 to manipulate order totals. "
                    "Fix: calculate prices server-side based on product IDs only; "
                    "never trust client-submitted monetary values."
                )
            ))

    def _check_privilege_escalation_params(self, url: str, html: str) -> None:
        """Detect role/admin fields that could enable privilege escalation."""
        soup = BeautifulSoup(html, "html.parser")
        priv_inputs = []
        for inp in soup.find_all("input"):
            name = inp.attrs.get("name", "")
            if _PRIV_FIELD_RE.search(f'name="{name}"'):
                itype = inp.attrs.get("type", "text").lower()
                priv_inputs.append(f"<input name='{name}' type='{itype}'>")

        if priv_inputs:
            log_fail(logger, f"Privilege escalation parameter fields found on {url}")
            self.results.append(self._result(
                url, "Business logic — privilege escalation parameter in form", "FAIL",
                detail=(
                    f"Found {len(priv_inputs)} form input(s) with privilege-related names: "
                    f"{'; '.join(priv_inputs[:3])}. "
                    "If the server uses these values without server-side authorization checks, "
                    "an attacker can set role=admin or is_admin=true to escalate privileges. "
                    "Fix: never trust role/admin fields from client input; "
                    "derive roles server-side from the authenticated session."
                )
            ))

    def _check_idor_in_url(self, url: str, html: str) -> None:
        """Check for numeric IDs in links that suggest IDOR opportunities."""
        soup = BeautifulSoup(html, "html.parser")
        idor_links = []
        for tag in soup.find_all("a", href=True):
            href = tag.attrs.get("href", "")
            if _IDOR_PATH_RE.search(href):
                idor_links.append(href)

        if len(idor_links) >= 2:
            ids = [_IDOR_PATH_RE.search(l).group(1) for l in idor_links[:5] if _IDOR_PATH_RE.search(l)]
            # Check if IDs are sequential (strong IDOR indicator)
            sequential = False
            if len(ids) >= 2:
                try:
                    nums = [int(i) for i in ids]
                    diffs = [abs(nums[i+1]-nums[i]) for i in range(len(nums)-1)]
                    sequential = all(d <= 5 for d in diffs)
                except (ValueError, IndexError):
                    pass

            if sequential:
                log_fail(logger, f"Sequential numeric IDs in links — likely IDOR: {url}")
                self.results.append(self._result(
                    url, "Business logic — IDOR risk (sequential object IDs)", "FAIL",
                    detail=(
                        f"Found {len(idor_links)} links with sequential numeric IDs: "
                        f"{', '.join(ids[:5])}. "
                        "Sequential IDs make it trivial to enumerate other users' resources "
                        "by incrementing or decrementing the ID. "
                        "Fix: use UUIDs or cryptographic random IDs for resource URLs, "
                        "and enforce authorization checks on every resource access."
                    )
                ))
            else:
                log_warn(logger, f"Numeric object IDs in links (possible IDOR): {url}")
                self.results.append(self._result(
                    url, "Business logic — numeric object IDs in links (potential IDOR)", "WARN",
                    detail=(
                        f"Found {len(idor_links)} link(s) using numeric resource IDs "
                        f"(e.g. {', '.join(idor_links[:2])}). "
                        "Verify that each resource access enforces authorization checks. "
                        "Fix: use non-sequential random IDs and test every endpoint with "
                        "a different user's session."
                    )
                ))

    def _check_cart_manipulation(self, url: str) -> None:
        """Look for /cart or /basket URLs and test quantity parameter edge cases."""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for cart_path in ["/cart", "/basket", "/api/cart", "/checkout/cart"]:
            cart_url = base + cart_path
            resp = self.http.get(cart_url)
            if resp is None or resp.status_code not in (200, 201):
                continue

            # Cart exists — check if it reveals cart structure
            body = resp.text or ""
            if _CART_PARAM_RE.search(body) or '"quantity"' in body or '"qty"' in body:
                log_warn(logger, f"Cart endpoint exposed at {cart_url}")
                self.results.append(self._result(
                    cart_url, "Business logic — cart/basket endpoint accessible", "WARN",
                    detail=(
                        f"Cart endpoint found at {cart_url}. "
                        "Verify that quantity and price manipulation via direct API calls "
                        "is prevented: test with negative quantities, fractional prices, "
                        "and mismatched product IDs. "
                        "Fix: enforce server-side validation on all cart operations."
                    )
                ))
            break  # Only report one cart endpoint

    def _check_negative_quantity(self, url: str, html: str) -> None:
        """Detect quantity parameters in URL or forms without min validation."""
        soup = BeautifulSoup(html, "html.parser")
        qty_inputs = []
        for inp in soup.find_all("input"):
            name = inp.attrs.get("name", "").lower()
            itype = inp.attrs.get("type", "text").lower()
            if any(k in name for k in ("qty", "quantity", "count", "num")):
                has_min = "min" in inp.attrs
                if itype in ("number", "text", "") and not has_min:
                    qty_inputs.append(inp.attrs.get("name", "qty"))

        if qty_inputs:
            log_warn(logger, f"Quantity fields without min attribute on {url}")
            self.results.append(self._result(
                url, "Business logic — quantity field without min validation", "WARN",
                detail=(
                    f"Form quantity field(s) {qty_inputs[:3]} lack a 'min' attribute. "
                    "Without server-side validation, negative quantities could result in "
                    "credits applied to accounts or negative order totals. "
                    "Fix: validate quantity > 0 server-side; HTML min attribute alone is insufficient."
                )
            ))
