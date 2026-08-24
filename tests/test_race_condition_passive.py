"""Tests for RaceConditionPassiveScanner."""
from unittest.mock import MagicMock
from tblue.scanner.race_condition_passive import RaceConditionPassiveScanner


def _scanner():
    s = RaceConditionPassiveScanner.__new__(RaceConditionPassiveScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_financial_no_idempotency():
    s = _scanner()
    s.http.get.return_value = _resp(
        '{"status": "success", "amount": 100}',
        headers={"Content-Type": "application/json"},
    )
    results = s.scan("http://example.com/api/transfer")
    types = [r["type"] for r in results]
    assert "race_condition_financial_no_idempotency" in types


def test_counter_no_optimistic_lock():
    s = _scanner()
    s.http.get.return_value = _resp(
        '{"balance": 500, "credits": 10, "status": "ok"}',
        headers={"Content-Type": "application/json"},
    )
    results = s.scan("http://example.com/api/account")
    types = [r["type"] for r in results]
    assert "race_condition_counter_no_optimistic_lock" in types


def test_toctou_pattern():
    s = _scanner()
    s.http.get.return_value = _resp(
        "if (balance > 0) { deductBalance(amount); }"
    )
    results = s.scan("http://example.com/checkout")
    types = [r["type"] for r in results]
    assert "race_condition_toctou_pattern" in types


def test_race_condition_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Regular page</html>")
    results = s.scan("http://example.com/about")
    assert results[0]["type"] == "race_condition_not_used"
    assert results[0]["status"] == "PASS"


def test_race_condition_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "race_condition_not_used"
