"""Extra branch coverage for tblue.scanner.sensitive_params."""

from tblue.scanner.sensitive_params import SensitiveParamScanner as SensitiveParamsScanner

URL = "https://example.com"


def _scanner():
    from unittest.mock import MagicMock
    session = MagicMock()
    return SensitiveParamsScanner(session)


def test_password_in_url_warns():
    """password= parameter with value in URL → WARN."""
    s = _scanner()
    results = s.scan(URL + "?password=secret123")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_api_key_in_url_warns():
    """api_key= parameter with value in URL → WARN."""
    s = _scanner()
    results = s.scan(URL + "?api_key=myapikey")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_clean_url_passes():
    """URL with only safe params → PASS result."""
    s = _scanner()
    results = s.scan(URL + "?page=1&sort=desc")
    assert any(r["status"] == "PASS" for r in results)


def test_token_in_url_warns():
    """token= parameter with a 4+ char value → WARN."""
    s = _scanner()
    results = s.scan(URL + "?token=eyJhbGciOiJIUzI1NiJ9")
    warns = [r for r in results if r["status"] == "WARN"]
    assert warns


def test_short_value_not_flagged():
    """Parameter value shorter than _MIN_VALUE_LEN (4) → not flagged."""
    s = _scanner()
    results = s.scan(URL + "?key=ab")
    warns = [r for r in results if r["status"] == "WARN"]
    assert not warns


def test_result_keys():
    """Results contain required keys."""
    s = _scanner()
    results = s.scan(URL + "?password=secret")
    for r in results:
        assert "url" in r and "status" in r and "type" in r
