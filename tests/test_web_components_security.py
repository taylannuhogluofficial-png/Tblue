"""Tests for WebComponentsSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.web_components_security import WebComponentsSecurityScanner


def _scanner():
    s = WebComponentsSecurityScanner.__new__(WebComponentsSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_shadow_dom_injection():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const root = el.attachShadow({mode: 'open'})\n"
        "root.shadowRoot\n"
        "const param = searchParams.get('template')\n"
        "root.innerHTML = param"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "shadow_dom_injection" in types


def test_template_clone_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const tmpl = document.querySelector('template')\n"
        "const clone = tmpl.content.cloneNode(searchParams.get('deep'))\n"
        "document.body.appendChild(clone)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "template_clone_from_param" in types


def test_slot_assigned_nodes_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const slot = shadowRoot.querySelector('slot')\n"
        "const nodes = slot.assignedNodes()\n"
        "sendBeacon('/collect', JSON.stringify(nodes.map(n => n.textContent)))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "slot_assigned_nodes_exfil" in types


def test_web_components_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No custom element definitions here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "web_components_not_used"
    assert results[0]["status"] == "PASS"


def test_web_components_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "web_components_not_used"
