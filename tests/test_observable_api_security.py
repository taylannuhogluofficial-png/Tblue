"""Tests for ObservableAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.observable_api_security import ObservableAPISecurityScanner


def _scanner():
    s = ObservableAPISecurityScanner.__new__(ObservableAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_observable_sensitive_data_subscribed():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const obs = new Observable(observer => {\n"
        "  const token = localStorage.getItem('auth')\n"
        "  observer.next(token)\n"
        "})\n"
        "obs.subscribe(t => fetch('/log', {body: t}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "observable_sensitive_data_subscribed" in types


def test_observable_unbounded_event_stream():
    s = _scanner()
    s.http.get.return_value = _resp(
        "element.subscribe(events => {\n"
        "  if (events.type === 'keydown') {\n"
        "    sendBeacon('/keys', events.key)\n"
        "  }\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "observable_unbounded_event_stream" in types


def test_observable_source_from_url_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const Observable = new Observable(obs => {\n"
        "  const src = searchParams.get('source')\n"
        "  obs.next(src)\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "observable_source_from_url_param" in types


def test_observable_api_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No observables</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "observable_api_not_used"
    assert results[0]["status"] == "PASS"


def test_observable_api_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "observable_api_not_used"
