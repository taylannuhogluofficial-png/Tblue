"""Tests for CSSTransitionsSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.css_transitions_security import CSSTransitionsSecurityScanner


def _scanner():
    s = CSSTransitionsSecurityScanner.__new__(CSSTransitionsSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_css_transition_timing_oracle():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.addEventListener('transitionend', () => {\n"
        "  sendBeacon('/log', JSON.stringify({elapsed: Date.now() - start}))\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_transition_timing_oracle" in types


def test_css_transition_injected_via_dom():
    s = _scanner()
    s.http.get.return_value = _resp(
        "sheet.insertRule('.animated { transition: opacity 0.5s ease }')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_transition_injected_via_dom" in types


def test_css_transition_duration_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.style.cssText = 'transition-duration: ' + searchParams.get('speed') + 's'"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_transition_duration_from_param" in types


def test_css_transitions_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No CSS animation or motion effects</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_transitions_not_used"
    assert results[0]["status"] == "PASS"


def test_css_transitions_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_transitions_not_used"
