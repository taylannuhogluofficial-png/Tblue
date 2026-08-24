"""Tests for AnchorPositioningSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.anchor_positioning_security import AnchorPositioningSecurityScanner


def _scanner():
    s = AnchorPositioningSecurityScanner.__new__(AnchorPositioningSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_anchor_positioning_style_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.setAttribute('style', 'anchor-name: --' + searchParams.get('anchor'))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "anchor_positioning_style_from_param" in types


def test_anchor_positioning_overlay_phishing():
    s = _scanner()
    s.http.get.return_value = _resp(
        ".overlay {\n"
        "  position: absolute\n"
        "  top: anchor(--password-field bottom)\n"
        "  left: anchor(--login start)\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "anchor_positioning_overlay_phishing" in types


def test_anchor_positioning_injected_via_dom():
    s = _scanner()
    s.http.get.return_value = _resp(
        "el.setAttribute('style', 'anchor-name: --myanchor')\n"
        "el.style.cssText = 'position-anchor: --btn'"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "anchor_positioning_injected_via_dom" in types


def test_anchor_positioning_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No positioning</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "anchor_positioning_not_used"
    assert results[0]["status"] == "PASS"


def test_anchor_positioning_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "anchor_positioning_not_used"
