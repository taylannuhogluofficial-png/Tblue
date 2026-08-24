"""Tests for PerformanceObserverSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.performance_observer_security import PerformanceObserverSecurityScanner


def _scanner():
    s = PerformanceObserverSecurityScanner.__new__(PerformanceObserverSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_performance_navigation_timing_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const navEntry = performance.getEntriesByType('navigation')[0]"
        "const timing = navEntry instanceof PerformanceNavigationTiming"
        "analytics('nav_timing', {data: navEntry.toJSON()})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "performance_navigation_timing_exfil" in types


def test_performance_resource_timing_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const resources = performance.getEntries()"
        "sendBeacon('/perf', JSON.stringify(resources))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "performance_resource_timing_exfil" in types


def test_performance_mark_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "performance.mark(searchParams.get('mark_name'))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "performance_mark_from_param" in types


def test_performance_observer_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No timing measurement code here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "performance_observer_not_used"
    assert results[0]["status"] == "PASS"


def test_performance_observer_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "performance_observer_not_used"
