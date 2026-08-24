"""Tests for DeserializationGadgetPassiveScanner."""
from unittest.mock import MagicMock
from tblue.scanner.deserialization_gadget_passive import DeserializationGadgetPassiveScanner


def _scanner():
    s = DeserializationGadgetPassiveScanner.__new__(DeserializationGadgetPassiveScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_php_serial_in_response():
    s = _scanner()
    s.http.get.return_value = _resp(
        'Set this cookie: O:8:"UserPref":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}'
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "deserialization_php_object_in_response" in types


def test_java_serial_in_response():
    s = _scanner()
    s.http.get.return_value = _resp(
        "Serialized data: rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "deserialization_java_serial_in_response" in types


def test_unserialize_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "unserialize($_GET['data'])"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "deserialization_unserialize_from_param" in types


def test_deserialization_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Regular page</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "deserialization_gadget_not_used"
    assert results[0]["status"] == "PASS"


def test_deserialization_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "deserialization_gadget_not_used"
