"""Tests for CSSFontPaletteSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.css_font_palette_security import CSSFontPaletteSecurityScanner


def _scanner():
    s = CSSFontPaletteSecurityScanner.__new__(CSSFontPaletteSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_css_font_from_url_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const face = new FontFace('Custom', searchParams.get('font'))\n"
        "document.fonts.add(face)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_font_from_url_param" in types


def test_css_font_loaded_externally():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const face = new FontFace('Custom', 'https://cdn.evil.com/font.woff2')\n"
        "document.fonts.add(face)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_font_loaded_externally" in types


def test_css_font_set_fingerprinting():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const fonts = []\n"
        "document.fonts.forEach(f => fonts.push({family: f.family, style: f.style}))\n"
        "sendBeacon('/fp', JSON.stringify(fonts))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "css_font_set_fingerprinting" in types


def test_css_font_palette_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No font palette</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_font_palette_not_used"
    assert results[0]["status"] == "PASS"


def test_css_font_palette_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "css_font_palette_not_used"
