"""Tests for CustomElementRegistrySecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.custom_element_registry_security import CustomElementRegistrySecurityScanner


def _scanner():
    s = CustomElementRegistrySecurityScanner.__new__(CustomElementRegistrySecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_custom_element_tag_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "customElements.define(searchParams.get('tag'), MyElement)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "custom_element_tag_from_param" in types


def test_custom_element_overrides_builtin():
    s = _scanner()
    s.http.get.return_value = _resp(
        "customElements.define('input', class extends HTMLElement {})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "custom_element_overrides_builtin" in types


def test_custom_element_connected_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "connectedCallback() {\n"
        "  fetch('/collect', {body: JSON.stringify(this.innerHTML)})\n"
        "  // transmits shadow DOM innerHTML on connect\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "custom_element_connected_exfil" in types


def test_custom_element_attr_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "attributeChangedCallback(name, old, val) {\n"
        "  eval(searchParams.get(name))\n"
        "}"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "custom_element_attr_from_param" in types


def test_custom_element_registry_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No web components defined</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "custom_element_registry_not_used"
    assert results[0]["status"] == "PASS"


def test_custom_element_registry_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "custom_element_registry_not_used"
