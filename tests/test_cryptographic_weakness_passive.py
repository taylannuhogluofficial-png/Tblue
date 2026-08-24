"""Tests for CryptographicWeaknessPassiveScanner."""
from unittest.mock import MagicMock
from tblue.scanner.cryptographic_weakness_passive import CryptographicWeaknessPassiveScanner


def _scanner():
    s = CryptographicWeaknessPassiveScanner.__new__(CryptographicWeaknessPassiveScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_weak_hash_md5():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const hash = createHash('md5').update(password).digest('hex');"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "cryptographic_weakness_weak_hash" in types


def test_ecb_mode():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const cipher = createCipheriv('aes-256-ecb', key, null);"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "cryptographic_weakness_ecb_mode" in types


def test_math_random_for_token():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const token = Math.random().toString(36).substr(2, 16);"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "cryptographic_weakness_math_random_for_secret" in types


def test_hardcoded_iv():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const iv = '0000000000000000'; const cipher = createCipheriv('aes-256-cbc', key, iv);"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "cryptographic_weakness_hardcoded_iv" in types


def test_crypto_weakness_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Regular static page</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "cryptographic_weakness_not_used"
    assert results[0]["status"] == "PASS"
