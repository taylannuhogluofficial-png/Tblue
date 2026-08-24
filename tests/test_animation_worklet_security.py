"""Tests for AnimationWorkletSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.animation_worklet_security import AnimationWorkletSecurityScanner


def _scanner():
    s = AnimationWorkletSecurityScanner.__new__(AnimationWorkletSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_animation_worklet_module_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "CSS.animationWorklet.addModule(searchParams.get('animator'))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "animation_worklet_module_from_param" in types


def test_animation_worklet_external_module():
    s = _scanner()
    s.http.get.return_value = _resp(
        "CSS.animationWorklet.addModule('https://cdn.example.com/animator.js')"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "animation_worklet_external_module" in types


def test_animation_worklet_timing_exfil():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const anim = new WorkletAnimation('scroll-driven', effect, timeline)\n"
        "const t = anim.currentTime\n"
        "sendBeacon('/timing', JSON.stringify({currentTime: t}))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "animation_worklet_timing_exfil" in types


def test_animation_worklet_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No CSS animation API worklet</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "animation_worklet_not_used"
    assert results[0]["status"] == "PASS"


def test_animation_worklet_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "animation_worklet_not_used"
