"""Tests for PopoverAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.popover_api_security import PopoverAPISecurityScanner


def _scanner():
    s = PopoverAPISecurityScanner.__new__(PopoverAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_popover_content_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const el = document.querySelector('#popup')\n"
        "el.innerHTML = searchParams.get('msg')\n"
        "el.showPopover()"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "popover_content_from_param" in types


def test_popover_phishing_overlay():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.querySelector('#loginPopover').showPopover()\n"
        "// credential form displayed as popover overlay\n"
        "// payment card details collected here"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "popover_phishing_overlay" in types


def test_popover_injected_via_dom():
    s = _scanner()
    s.http.get.return_value = _resp(
        "popupEl.innerHTML = userMessage\n"
        "popupEl.showPopover()"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "popover_injected_via_dom" in types


def test_popover_api_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No overlay floating UI</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "popover_api_not_used"
    assert results[0]["status"] == "PASS"


def test_popover_api_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "popover_api_not_used"
