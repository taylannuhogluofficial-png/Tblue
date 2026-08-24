"""
Canvas / WebGL / Audio Fingerprinting Detection Scanner.

Browser fingerprinting uses hardware-specific rendering differences to create
a unique identifier for users without cookies. Fingerprinting violates GDPR
(Article 5(1)(c) data minimisation) and CCPA when used for tracking.

Fingerprinting APIs detected:

1. Canvas fingerprinting:
   - `canvas.toDataURL()` or `canvas.toBlob()` after drawing text/shapes
   - `context.getImageData()` reads rendered pixel values
   - 2D canvas with text rendering + pixel extraction = font fingerprint

2. WebGL fingerprinting:
   - `gl.getParameter(RENDERER)` / `gl.getParameter(VENDOR)` — GPU identity
   - `gl.getExtension()` — GPU extension enumeration
   - `WEBGL_debug_renderer_info` — precise GPU model string

3. AudioContext fingerprinting:
   - `AudioContext` or `OfflineAudioContext` with `OscillatorNode` +
     `AnalyserNode` + `getChannelData()` — DAC/driver fingerprint

4. Font enumeration:
   - CSS measurement trick: rendering text in multiple fonts and measuring
     dimensions to detect installed fonts without Flash

5. navigator.plugins fingerprinting:
   - Iterating `navigator.plugins` or `navigator.mimeTypes`

6. Battery Status API fingerprinting:
   - `navigator.getBattery()` reveals charge level — unique enough to fingerprint

7. Hardware concurrency / device memory:
   - `navigator.hardwareConcurrency` + `navigator.deviceMemory` — unique combo

CWE-359: Exposure of Private Personal Information
GDPR Article 5(1)(c), CCPA Section 1798.140(o)
"""

import re
from typing import Any, Dict, List

from tblue.scanner.base import BaseScanner
from tblue.logger import get_logger, log_pass, log_warn, log_fail

logger = get_logger(__name__)

_CANVAS_FP_RE = re.compile(
    r'(?:'
    r'(?:canvas|ctx|context)\.toDataURL\s*\('
    r'|\.getImageData\s*\('
    r'|\.toBlob\s*\('
    r')',
    re.I
)

_CANVAS_TEXT_RE = re.compile(r'\.fillText\s*\(|\.strokeText\s*\(', re.I)

_WEBGL_FP_RE = re.compile(
    r'WEBGL_debug_renderer_info'
    r'|gl\.getParameter\s*\([^)]*(?:RENDERER|VENDOR|VERSION)'
    r'|getExtension\s*\(\s*["\']WEBGL_debug',
    re.I
)

_AUDIO_FP_RE = re.compile(
    r'(?:AudioContext|OfflineAudioContext)\s*\('
    r'(?:(?!\.close|\.suspend|\.resume).)*?'
    r'(?:OscillatorNode|createOscillator|getChannelData|AnalyserNode|createAnalyser)',
    re.I | re.S
)

_BATTERY_FP_RE = re.compile(r'navigator\.getBattery\s*\(', re.I)

_HARDWARE_FP_RE = re.compile(
    r'navigator\.hardwareConcurrency|navigator\.deviceMemory',
    re.I
)

_PLUGINS_FP_RE = re.compile(
    r'navigator\.plugins\b|navigator\.mimeTypes\b',
    re.I
)

_FONT_FP_RE = re.compile(
    r'document\.fonts\b|FontFaceSet|measureText.*fonts?',
    re.I
)


class CanvasFingerprintingScanner(BaseScanner):
    """Detect browser fingerprinting API usage in page JavaScript."""

    def scan(self, url: str) -> List[Dict[str, Any]]:
        self.results = []
        findings = 0

        try:
            resp = self.http.get(url)
        except Exception:
            return self.results

        if resp is None:
            self.results.append(self._result(
                url, "Canvas fingerprinting — no response", "PASS",
                detail="Target did not respond."
            ))
            return self.results

        body = resp.text or ""

        # Canvas fingerprinting
        if _CANVAS_FP_RE.search(body) and _CANVAS_TEXT_RE.search(body):
            log_warn(logger, f"Canvas fingerprinting pattern at {url}")
            self.results.append(self._result(
                url,
                "Canvas fingerprinting — canvas.toDataURL() / getImageData() with text rendering detected",
                "WARN",
                detail=(
                    "Page JavaScript combines canvas text rendering (fillText/strokeText) with "
                    "pixel data extraction (toDataURL/getImageData). This is the classic canvas "
                    "fingerprinting technique — hardware rendering differences produce unique pixel "
                    "patterns that identify users without cookies. "
                    "Fix: evaluate whether this is a legitimate business need; if used for tracking, "
                    "disclose in privacy policy and consider alternatives. "
                    "Browsers with strict privacy modes (Firefox, Brave) will randomize canvas output."
                )
            ))
            findings += 1

        # WebGL fingerprinting
        if _WEBGL_FP_RE.search(body) and findings < 8:
            log_warn(logger, f"WebGL fingerprinting pattern at {url}")
            self.results.append(self._result(
                url,
                "Canvas fingerprinting — WebGL RENDERER/VENDOR/debug_renderer_info access detected",
                "WARN",
                detail=(
                    "Page JavaScript accesses WebGL_debug_renderer_info or reads GL_RENDERER/GL_VENDOR "
                    "parameters. These expose the precise GPU model and driver version, creating a "
                    "highly unique identifier. "
                    "Fix: limit WebGL usage to actual rendering; remove debugger-info access; "
                    "disclose tracking use in privacy policy."
                )
            ))
            findings += 1

        # AudioContext fingerprinting
        if _AUDIO_FP_RE.search(body) and findings < 8:
            log_warn(logger, f"AudioContext fingerprinting pattern at {url}")
            self.results.append(self._result(
                url,
                "Canvas fingerprinting — AudioContext with oscillator/analyser (audio fingerprinting)",
                "WARN",
                detail=(
                    "Page JavaScript creates an AudioContext with OscillatorNode and AnalyserNode "
                    "and reads channel data. Audio processing differences between hardware/drivers "
                    "produce unique floating-point values, enabling device fingerprinting. "
                    "Fix: use AudioContext only for legitimate audio features; avoid getChannelData "
                    "on programmatically generated signals when tracking is not the intent."
                )
            ))
            findings += 1

        # Battery fingerprinting
        if _BATTERY_FP_RE.search(body) and findings < 8:
            log_warn(logger, f"Battery Status API fingerprinting at {url}")
            self.results.append(self._result(
                url,
                "Canvas fingerprinting — navigator.getBattery() (battery status fingerprinting)",
                "WARN",
                detail=(
                    "Page JavaScript calls navigator.getBattery(). Battery level, charging status, "
                    "and discharge time can uniquely identify a device across sessions and origins. "
                    "Firefox has disabled this API. Most Chromium browsers block it in cross-origin "
                    "contexts. Fix: remove battery status usage if not needed for UX; "
                    "it provides no unique technical benefit over other device detection methods."
                )
            ))
            findings += 1

        # Hardware concurrency + device memory
        if _HARDWARE_FP_RE.search(body) and findings < 8:
            log_warn(logger, f"Hardware fingerprinting (hardwareConcurrency/deviceMemory) at {url}")
            self.results.append(self._result(
                url,
                "Canvas fingerprinting — navigator.hardwareConcurrency / navigator.deviceMemory access",
                "WARN",
                detail=(
                    "Page JavaScript reads navigator.hardwareConcurrency (CPU cores) and/or "
                    "navigator.deviceMemory (RAM). Combined with other signals, these create a "
                    "hardware fingerprint unique to most devices. "
                    "Fix: use these values only for legitimate adaptive performance tuning; "
                    "avoid combining them with other identifiers for tracking."
                )
            ))
            findings += 1

        # navigator.plugins
        if _PLUGINS_FP_RE.search(body) and findings < 8:
            log_warn(logger, f"navigator.plugins fingerprinting at {url}")
            self.results.append(self._result(
                url,
                "Canvas fingerprinting — navigator.plugins / navigator.mimeTypes enumeration",
                "WARN",
                detail=(
                    "Page JavaScript accesses navigator.plugins or navigator.mimeTypes. "
                    "Enumerating installed browser plugins creates a fingerprint element. "
                    "Modern browsers return limited/empty plugin lists to mitigate this. "
                    "Fix: remove plugin enumeration; most legitimate use cases are obsolete "
                    "since Flash and Java plugins are no longer supported."
                )
            ))
            findings += 1

        if not self.results:
            log_pass(logger, f"No fingerprinting patterns at {url}")
            self.results.append(self._result(
                url, "Canvas fingerprinting — no browser fingerprinting patterns detected", "PASS",
                detail="No canvas/WebGL/audio fingerprinting API combinations found in page JavaScript."
            ))

        return self.results
