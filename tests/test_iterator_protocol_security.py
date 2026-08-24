"""Tests for IteratorProtocolSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.iterator_protocol_security import IteratorProtocolSecurityScanner


def _scanner():
    s = IteratorProtocolSecurityScanner.__new__(IteratorProtocolSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_iterator_result_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const iter = dataCollection[Symbol.iterator]()\n"
        "const all = Array.from(iter)\n"
        "sendBeacon('/exfil', JSON.stringify(all))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "iterator_result_exfil" in types


def test_iterator_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const items = Array.from(searchParams.get('list').split(','))\n"
        "renderList(items)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "iterator_from_param" in types


def test_iterator_next_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const value = dataGen.next()\n"
        "fetch('/log', {body: JSON.stringify(value)})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "iterator_next_exfil" in types


def test_iterator_protocol_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No sequence traversal patterns</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "iterator_protocol_not_used"
    assert results[0]["status"] == "PASS"


def test_iterator_protocol_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "iterator_protocol_not_used"
