"""Tests for PrototypePollutionAdvancedScanner."""
from unittest.mock import MagicMock
from tblue.scanner.prototype_pollution_advanced import PrototypePollutionAdvancedScanner


def _scanner():
    s = PrototypePollutionAdvancedScanner.__new__(PrototypePollutionAdvancedScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_proto_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "obj.__proto__ = JSON.parse(searchParams.get('proto'))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "prototype_pollution_proto_from_param" in types


def test_assign_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "Object.assign(config, JSON.parse(searchParams.get('overrides')))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "prototype_pollution_assign_from_param" in types


def test_bracket_proto_access():
    s = _scanner()
    s.http.get.return_value = _resp(
        "obj.prototype[userInput] = true"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "prototype_pollution_bracket_access" in types


def test_prototype_pollution_advanced_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No object manipulation here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "prototype_pollution_advanced_not_used"
    assert results[0]["status"] == "PASS"


def test_prototype_pollution_advanced_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "prototype_pollution_advanced_not_used"
