"""Tests for FontAccessSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.font_access_security import FontAccessSecurityScanner


def _scanner():
    s = FontAccessSecurityScanner.__new__(FontAccessSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_font_access_fingerprinting():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const fonts = await queryLocalFonts()\n"
        "const families = fonts.map(f => f.family)\n"
        "sendBeacon('/fp', JSON.stringify({fingerprint: families.join(','), deviceId: userId}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "font_access_fingerprinting" in types


def test_font_access_enumerate_all():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const localFonts = await queryLocalFonts()\n"
        "const count = localFonts.length\n"
        "const all = localFonts.map(f => f.postscriptName)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "font_access_enumerate_all" in types


def test_font_access_list_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const fonts = await queryLocalFonts()\n"
        "fetch('/profile', {method: 'POST', body: JSON.stringify({fonts: fonts})})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "font_access_list_exfiltrated" in types


def test_font_access_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No local typeface API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "font_access_not_used"
    assert results[0]["status"] == "PASS"


def test_font_access_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "font_access_not_used"
