"""Tests for ColorSchemeSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.color_scheme_security import ColorSchemeSecurityScanner


def _scanner():
    s = ColorSchemeSecurityScanner.__new__(ColorSchemeSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_color_scheme_fingerprinting():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const dark = window.matchMedia('(prefers-color-scheme: dark)').matches\n"
        "sendBeacon('/fp', JSON.stringify({darkMode: dark}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "color_scheme_fingerprinting" in types


def test_media_preference_batch_probe():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const motion = window.matchMedia('(prefers-reduced-motion: reduce)').matches\n"
        "fetch('/profile', {body: JSON.stringify({reducedMotion: motion})})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "media_preference_batch_probe" in types


def test_forced_color_mode_fingerprinting():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const forced = window.matchMedia('(forced-colors: active)').matches\n"
        "sendBeacon('/analytics', JSON.stringify({forcedColors: forced}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "forced_color_mode_fingerprinting" in types


def test_color_scheme_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No theme or contrast preference API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "color_scheme_not_used"
    assert results[0]["status"] == "PASS"


def test_color_scheme_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "color_scheme_not_used"
