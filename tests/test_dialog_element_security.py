"""Tests for DialogElementSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.dialog_element_security import DialogElementSecurityScanner


def _scanner():
    s = DialogElementSecurityScanner.__new__(DialogElementSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_dialog_content_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const msg = searchParams.get('notice')\n"
        "document.querySelector('dialog').showModal()"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "dialog_content_from_param" in types


def test_dialog_phishing_modal():
    s = _scanner()
    s.http.get.return_value = _resp(
        "document.querySelector('#loginModal').showModal()\n"
        "// password field and credential form displayed"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "dialog_phishing_modal" in types


def test_dialog_injected_via_dom():
    s = _scanner()
    s.http.get.return_value = _resp(
        "dlg.innerHTML = '<form>' + userContent + '</form>'\n"
        "dlg.showModal()"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "dialog_injected_via_dom" in types


def test_dialog_return_value_exfiltrated():
    s = _scanner()
    s.http.get.return_value = _resp(
        "dialog.addEventListener('close', () => {\n"
        "  const answer = dialog.returnValue\n"
        "  fetch('/submit', {body: JSON.stringify({answer})})\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "dialog_return_value_exfiltrated" in types


def test_dialog_element_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No modal or overlay element</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "dialog_element_not_used"
    assert results[0]["status"] == "PASS"
