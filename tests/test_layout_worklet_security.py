"""Tests for LayoutWorkletSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.layout_worklet_security import LayoutWorkletSecurityScanner


def _scanner():
    s = LayoutWorkletSecurityScanner.__new__(LayoutWorkletSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_layout_worklet_module_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "CSS.layoutWorklet.addModule(searchParams.get('layout'))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "layout_worklet_module_from_param" in types


def test_layout_worklet_external_module():
    s = _scanner()
    s.http.get.return_value = _resp(
        "CSS.layoutWorklet.addModule('https://cdn.example.com/layout.js')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "layout_worklet_external_module" in types


def test_layout_worklet_timing_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "registerLayout('custom', class {\n"
        "  async layout(children, edges, constraints, styleMap) {\n"
        "    const t0 = performance.now()\n"
        "    const fragments = await layoutChildren(children)\n"
        "    postMessage({time: performance.now() - t0})\n"
        "    return {autoBlockSize: 0, childFragments: fragments}\n"
        "  }\n"
        "})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "layout_worklet_timing_exfil" in types


def test_layout_worklet_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No CSS layout worklet API</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "layout_worklet_not_used"
    assert results[0]["status"] == "PASS"


def test_layout_worklet_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "layout_worklet_not_used"
