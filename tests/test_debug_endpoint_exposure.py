"""Tests for DebugEndpointExposureScanner."""
from unittest.mock import MagicMock
from tblue.scanner.debug_endpoint_exposure import DebugEndpointExposureScanner


def _scanner():
    s = DebugEndpointExposureScanner.__new__(DebugEndpointExposureScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_werkzeug_debugger():
    s = _scanner()
    s.http.get.return_value = _resp(
        "Werkzeug Debugger — The debugger caught an exception in your WSGI app."
    )
    results = s.scan("http://example.com/error")
    types = [r["type"] for r in results]
    assert "debug_endpoint_werkzeug_debugger" in types


def test_django_toolbar():
    s = _scanner()
    s.http.get.return_value = _resp(
        '<div id="djDebug">django-debug-toolbar panel</div>'
    )
    results = s.scan("http://example.com/")
    types = [r["type"] for r in results]
    assert "debug_endpoint_django_toolbar" in types


def test_stack_trace_exposed():
    s = _scanner()
    s.http.get.return_value = _resp(
        "Traceback (most recent call last):\n"
        '  File "/app/views.py", line 42, in get_user\n'
        "    user = User.objects.get(pk=user_id)\n"
        "DoesNotExist: User matching query does not exist."
    )
    results = s.scan("http://example.com/api/user")
    types = [r["type"] for r in results]
    assert "debug_endpoint_stack_trace_exposed" in types


def test_debug_endpoint_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html><body><h1>Welcome</h1></body></html>")
    results = s.scan("http://example.com/")
    assert results[0]["type"] == "debug_endpoint_not_used"
    assert results[0]["status"] == "PASS"


def test_debug_endpoint_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com/")
    assert results[0]["type"] == "debug_endpoint_not_used"
