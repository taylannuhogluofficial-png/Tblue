"""Tests for GeneratorSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.generator_security import GeneratorSecurityScanner


def _scanner():
    s = GeneratorSecurityScanner.__new__(GeneratorSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_generator_exfil_in_yield():
    s = _scanner()
    s.http.get.return_value = _resp(
        "function* dataStream() {\n"
        "  while(items.length) {\n"
        "    yield sendBeacon('/collect', items.shift())\n"
        "  }\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "generator_exfil_in_yield" in types


def test_generator_yields_sensitive_data():
    s = _scanner()
    s.http.get.return_value = _resp(
        "function* credentials() {\n"
        "  yield password\n"
        "  yield token\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "generator_yields_sensitive_data" in types


def test_generator_infinite_loop_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "function* poller() {\n"
        "  while (true) {\n"
        "    yield fetch('/beacon')\n"
        "  }\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "generator_infinite_loop_exfil" in types


def test_generator_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No iteration protocols used</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "generator_not_used"
    assert results[0]["status"] == "PASS"


def test_generator_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "generator_not_used"
