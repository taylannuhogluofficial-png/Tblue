"""Gamepad API security scanner — passive detection of gamepad input surveillance."""
import re
from .base import BaseScanner

_GP_ANY_RE = re.compile(
    r'(?:navigator\.getGamepads\s*\(|GamepadEvent\b|gamepadconnected\b|Gamepad\b|getGamepads\s*\(\s*\))',
    re.I,
)

_GP_INPUT_EXFIL_RE = re.compile(
    r'getGamepads\s*\([^)]*\)[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_GP_BUTTON_CONTINUOUS_RE = re.compile(
    r'getGamepads\s*\([^)]*\)[^;]{0,200}'
    r'(?:buttons|axes)[^;]{0,200}'
    r'(?:requestAnimationFrame|setInterval)',
    re.I,
)

_GP_FINGERPRINT_RE = re.compile(
    r'GamepadEvent\b[^;]{0,200}(?:id|mapping|buttons\.length|axes\.length)[^;]{0,200}'
    r'(?:fetch|sendBeacon|analytics)',
    re.I,
)

_GP_KEYSTROKE_INFER_RE = re.compile(
    r'getGamepads\s*\([^)]*\)[^;]{0,300}'
    r'(?:password|token|input|keydown|keypress|keyboard)',
    re.I,
)


class GamepadSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "gamepad_not_used", "PASS")]

        body = resp.text

        if not _GP_ANY_RE.search(body):
            return [self._result(url, "gamepad_not_used", "PASS")]

        findings = []

        if _GP_INPUT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "gamepad_input_exfiltrated", "FAIL",
                detail="navigator.getGamepads() output transmitted to remote — gamepad state surveillance.",
            ))

        if _GP_BUTTON_CONTINUOUS_RE.search(body):
            findings.append(self._result(
                url, "gamepad_continuous_polling", "WARN",
                detail="Gamepad buttons/axes polled continuously via rAF/setInterval — persistent input monitoring.",
            ))

        if _GP_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "gamepad_fingerprinting", "WARN",
                detail="GamepadEvent id/mapping/axis count transmitted to remote — gamepad-based fingerprinting.",
            ))

        if _GP_KEYSTROKE_INFER_RE.search(body):
            findings.append(self._result(
                url, "gamepad_keystroke_inference", "FAIL",
                detail="Gamepad polling correlated with keyboard/password inputs — covert side-channel inference.",
            ))

        return findings or [self._result(url, "gamepad_safe", "PASS")]
