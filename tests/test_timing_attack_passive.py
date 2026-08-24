"""Tests for TimingAttackPassiveScanner."""
from unittest.mock import MagicMock
from tblue.scanner.timing_attack_passive import TimingAttackPassiveScanner


def _scanner():
    s = TimingAttackPassiveScanner.__new__(TimingAttackPassiveScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_naive_equality_compare():
    s = _scanner()
    s.http.get.return_value = _resp(
        "if (token === submittedToken) { grantAccess(); }"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "timing_attack_naive_equality_compare" in types


def test_string_compare_equals():
    s = _scanner()
    s.http.get.return_value = _resp(
        "if (storedHash.equals(computedHash)) { return true; }"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "timing_attack_string_compare" in types


def test_response_time_header():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const hmac = crypto.createHmac('sha256', secret).digest('hex');",
        headers={"X-Response-Time": "42ms"},
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "timing_attack_response_time_header" in types


def test_timing_attack_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Regular page</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "timing_attack_not_used"
    assert results[0]["status"] == "PASS"


def test_timing_attack_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "timing_attack_not_used"
