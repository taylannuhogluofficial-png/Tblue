"""Integer Overflow Passive scanner — passive detection of integer overflow and arithmetic vulnerability patterns."""
import re
from .base import BaseScanner

_IO_ANY_RE = re.compile(
    r'(?:parseInt|parseFloat|Number\s*\(|Math\.floor|'
    r'BigInt|\bquantity\b|\bamount\b|\bprice\b|'
    r'total\s*\*|count\s*\+|MAX_SAFE_INTEGER)',
    re.I,
)

_IO_PARSE_INT_NO_BOUNDS_RE = re.compile(
    r'parseInt\s*\(\s*(?:searchParams|req\.body|req\.query|location\.hash)'
    r'[^;]{0,200}'
    r'(?!\s*(?:if\s*\(|Math\.min|Math\.max|>\s*0|<\s*\d|>=\s*0|<=\s*\d|\|\|\s*0|\?\s*0))',
    re.I,
)

_IO_MULTIPLY_NO_CHECK_RE = re.compile(
    r'(?:price|quantity|amount|count|rate)\s*\*\s*'
    r'(?:parseInt|parseFloat|Number)\s*\('
    r'(?:searchParams|req\.body|req\.query)',
    re.I,
)

_IO_NEGATIVE_VALUE_NO_CHECK_RE = re.compile(
    r'(?:balance|total|amount|quantity|count)\s*-=\s*'
    r'(?:parseInt|parseFloat|Number)\s*\('
    r'(?:searchParams|req\.body|req\.query)',
    re.I,
)

_IO_MAX_SAFE_INTEGER_RE = re.compile(
    r'(?:Number\.MAX_SAFE_INTEGER|Number\.MAX_VALUE|'
    r'2147483647|9007199254740991|\bINT_MAX\b)',
    re.I,
)

_IO_OVERFLOW_PATTERN_RE = re.compile(
    r'(?:0xffffffff|0x7fffffff|\bMAX_INT\b|'
    r'(?:\d{10,})\s*\+\s*(?:\d{10,})|'
    r'new\s+Array\s*\(\s*(?:searchParams|req\.body|Number))',
    re.I,
)

_IO_PRICE_NEGATIVE_BYPASS_RE = re.compile(
    r'(?:total|subtotal|price|amount)\s*=\s*'
    r'(?:price|quantity|amount|count|rate)\s*\*\s*'
    r'(?:parseInt|parseFloat|Number)\s*\('
    r'(?![\s\S]{0,100}(?:Math\.abs|>\s*0|>=\s*1|\bMath\.max))',
    re.I | re.S,
)


class IntegerOverflowPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "integer_overflow_not_used", "PASS")]

        body = resp.text
        if not _IO_ANY_RE.search(body):
            return [self._result(url, "integer_overflow_not_used", "PASS")]

        findings = []

        if _IO_MULTIPLY_NO_CHECK_RE.search(body):
            findings.append(self._result(
                url, "integer_overflow_price_multiply", "FAIL",
                detail="Price/quantity multiplication with URL parameter or req.body without bounds check — attacker submits negative quantity to receive credit instead of being charged, or MAX_SAFE_INTEGER to overflow total to negative; classic e-commerce price manipulation.",
            ))

        if _IO_NEGATIVE_VALUE_NO_CHECK_RE.search(body):
            findings.append(self._result(
                url, "integer_overflow_negative_decrement", "FAIL",
                detail="balance/total decremented by URL parameter value without checking sign — attacker submits negative amount to increase balance instead of decreasing it; negative quantity in deduction becomes an addition.",
            ))

        if _IO_PARSE_INT_NO_BOUNDS_RE.search(body):
            findings.append(self._result(
                url, "integer_overflow_parse_int_no_bounds", "WARN",
                detail="parseInt() on URL parameter without min/max bounds checking — unchecked integer conversion enables negative value injection (deductions become additions), zero quantity bypass (free items), or extremely large values causing DoS via memory allocation.",
            ))

        if _IO_PRICE_NEGATIVE_BYPASS_RE.search(body):
            findings.append(self._result(
                url, "integer_overflow_price_negative_bypass", "FAIL",
                detail="Total price calculated as price * quantity without Math.abs() or > 0 guard — attacker supplies negative quantity to get negative total; some payment processors interpret negative total as a refund or credit to the attacker.",
            ))

        if _IO_OVERFLOW_PATTERN_RE.search(body):
            findings.append(self._result(
                url, "integer_overflow_large_value_pattern", "WARN",
                detail="Extremely large integer constant or max-value pattern detected — MAX_INT/0x7fffffff/2^53-1 boundary values in arithmetic operations; overflow at these boundaries wraps to negative or zero, enabling bypass of positive-value checks.",
            ))

        return findings or [self._result(url, "integer_overflow_safe", "PASS")]
