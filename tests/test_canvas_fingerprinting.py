"""Tests for CanvasFingerprintingScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.canvas_fingerprinting import CanvasFingerprintingScanner

URL = "https://example.com"


class TestCanvasFingerprinting(unittest.TestCase):
    def _make(self):
        s = CanvasFingerprintingScanner.__new__(CanvasFingerprintingScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body=""):
        r = MagicMock()
        r.status_code = 200
        r.text = body
        r.headers = {}
        return r

    def _page(self, js):
        return f"<html><body><script>{js}</script></body></html>"

    # ── Canvas fingerprinting ─────────────────────────────────────────────────

    def test_canvas_fingerprint_warns(self):
        body = self._page("""
var canvas = document.createElement('canvas');
var ctx = canvas.getContext('2d');
ctx.fillText('Cwm fjordbank glyphs vext quiz', 2, 15);
var fp = canvas.toDataURL();
""")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("canvas" in r["type"].lower() for r in warns))

    # ── WebGL fingerprinting ──────────────────────────────────────────────────

    def test_webgl_fingerprint_warns(self):
        body = self._page("""
var gl = canvas.getContext('webgl');
var ext = gl.getExtension('WEBGL_debug_renderer_info');
var renderer = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
""")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("webgl" in r["type"].lower() for r in warns))

    # ── AudioContext fingerprinting ───────────────────────────────────────────

    def test_audio_fingerprint_warns(self):
        body = self._page("""
var ctx = new AudioContext();
var osc = ctx.createOscillator();
var analyser = ctx.createAnalyser();
osc.connect(analyser);
var data = new Float32Array(analyser.frequencyBinCount);
analyser.getChannelData(0);
""")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("audio" in r["type"].lower() for r in warns))

    # ── Battery fingerprinting ────────────────────────────────────────────────

    def test_battery_fingerprint_warns(self):
        body = self._page("navigator.getBattery().then(function(battery) { console.log(battery.level); });")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("battery" in r["type"].lower() for r in warns))

    # ── Hardware concurrency fingerprinting ───────────────────────────────────

    def test_hardware_concurrency_warns(self):
        body = self._page("var cores = navigator.hardwareConcurrency; var mem = navigator.deviceMemory;")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("hardware" in r["type"].lower() or "concurrency" in r["type"].lower() or "memory" in r["type"].lower() for r in warns))

    # ── navigator.plugins fingerprinting ─────────────────────────────────────

    def test_plugins_fingerprinting_warns(self):
        body = self._page("var plugins = Array.from(navigator.plugins).map(p => p.name);")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("plugin" in r["type"].lower() for r in warns))

    # ── Clean page passes ─────────────────────────────────────────────────────

    def test_clean_page_passes(self):
        body = self._page("var x = document.getElementById('canvas'); x.getContext('2d').fillRect(0, 0, 100, 100);")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body)
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))

    # ── No response ───────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
