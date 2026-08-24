"""Tests for IntersectionObserverSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.intersection_observer_security import IntersectionObserverSecurityScanner


def _scanner():
    s = IntersectionObserverSecurityScanner.__new__(IntersectionObserverSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_intersection_visibility_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const obs = new IntersectionObserver(entries => {"
        "  entries.forEach(e => {"
        "    if (e.isIntersecting) sendBeacon('/view', e.target.id)"
        "  })"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "intersection_visibility_exfil" in types


def test_intersection_ratio_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const obs = new IntersectionObserver(entries => {"
        "  const ratio = entries[0].intersectionRatio"
        "  analytics('view_depth', {ratio: ratio})"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "intersection_ratio_exfil" in types


def test_intersection_observer_sensitive_target():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const io = new IntersectionObserver(cb)"
        "io.observe(document.querySelector('#password').login)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "intersection_observer_sensitive_target" in types


def test_intersection_observer_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No viewport monitoring code here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "intersection_observer_not_used"
    assert results[0]["status"] == "PASS"


def test_intersection_observer_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "intersection_observer_not_used"
