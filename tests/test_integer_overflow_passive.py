"""Tests for IntegerOverflowPassiveScanner."""
from unittest.mock import MagicMock
from tblue.scanner.integer_overflow_passive import IntegerOverflowPassiveScanner


def _scanner():
    s = IntegerOverflowPassiveScanner.__new__(IntegerOverflowPassiveScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_price_multiply_overflow():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const total = price * parseInt(req.body.quantity); charge(total);"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "integer_overflow_price_multiply" in types


def test_negative_decrement():
    s = _scanner()
    s.http.get.return_value = _resp(
        "balance -= parseInt(req.body.amount); updateWallet(balance);"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "integer_overflow_negative_decrement" in types


def test_parse_int_no_bounds():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const count = parseInt(searchParams.get('count')); fetchItems(count);"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "integer_overflow_parse_int_no_bounds" in types


def test_integer_overflow_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Static page with no numeric operations</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "integer_overflow_not_used"
    assert results[0]["status"] == "PASS"


def test_integer_overflow_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "integer_overflow_not_used"
