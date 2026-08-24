"""Tests for InsecureDataExposureScanner."""
from unittest.mock import MagicMock
from tblue.scanner.insecure_data_exposure import InsecureDataExposureScanner


def _scanner():
    s = InsecureDataExposureScanner.__new__(InsecureDataExposureScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_private_key_in_response():
    s = _scanner()
    s.http.get.return_value = _resp(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "insecure_data_exposure_private_key" in types


def test_aws_key_in_response():
    s = _scanner()
    s.http.get.return_value = _resp(
        '{"key": "AKIAIOSFODNN7EXAMPLE", "region": "us-east-1"}'
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "insecure_data_exposure_aws_key" in types


def test_secret_in_json():
    s = _scanner()
    s.http.get.return_value = _resp(
        '{"user": "admin", "api_key": "sk_live_supersecretkey123456", "active": true}'
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "insecure_data_exposure_secret_in_json" in types


def test_jwt_in_body():
    s = _scanner()
    s.http.get.return_value = _resp(
        '{"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}'
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "insecure_data_exposure_jwt_in_body" in types


def test_insecure_data_exposure_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Hello world</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "insecure_data_exposure_not_used"
    assert results[0]["status"] == "PASS"
