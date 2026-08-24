"""Keyboard Lock API security scanner — passive detection of keyboard capture misuse."""
import re
from .base import BaseScanner

_KL_ANY_RE = re.compile(
    r'(?:navigator\.keyboard\b|keyboard\.lock\s*\(|keyboard\.unlock\s*\(|KeyboardLayoutMap\b|getLayoutMap\s*\(\s*\))',
    re.I,
)

_KL_ALL_KEYS_LOCKED_RE = re.compile(
    r'keyboard\.lock\s*\(\s*\[\s*\]',
    re.I,
)

_KL_LAYOUT_FINGERPRINT_RE = re.compile(
    r'getLayoutMap\s*\(\s*\)[^;]{0,300}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_KL_SYSTEM_KEY_LOCK_RE = re.compile(
    r'keyboard\.lock\s*\([^)]*(?:Escape|F1|F2|F3|F4|F5|F6|F7|F8|F9|F10|F11|F12|'
    r'MetaLeft|MetaRight|AltLeft|AltRight|ControlLeft|ControlRight)[^)]*\)',
    re.I,
)

_KL_AUTO_LOCK_RE = re.compile(
    r'(?:DOMContentLoaded|pageshow|fullscreenchange)[^;]{0,200}keyboard\.lock\s*\(',
    re.I,
)


class KeyboardLockSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "keyboard_lock_not_used", "PASS")]

        body = resp.text

        if not _KL_ANY_RE.search(body):
            return [self._result(url, "keyboard_lock_not_used", "PASS")]

        findings = []

        if _KL_ALL_KEYS_LOCKED_RE.search(body):
            findings.append(self._result(
                url, "keyboard_all_keys_locked", "FAIL",
                detail="keyboard.lock([]) captures all keys — prevents system keyboard shortcuts and escape.",
            ))

        if _KL_LAYOUT_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "keyboard_layout_fingerprinting", "WARN",
                detail="KeyboardLayoutMap data transmitted to remote — keyboard locale fingerprinting.",
            ))

        if _KL_SYSTEM_KEY_LOCK_RE.search(body):
            findings.append(self._result(
                url, "keyboard_system_key_locked", "FAIL",
                detail="System keys (Escape/Meta/Alt/F-keys) captured via keyboard.lock() — prevents user escape from page.",
            ))

        if _KL_AUTO_LOCK_RE.search(body):
            findings.append(self._result(
                url, "keyboard_lock_auto_activated", "WARN",
                detail="keyboard.lock() triggered on page/fullscreen load — automatic keyboard capture without explicit user action.",
            ))

        return findings or [self._result(url, "keyboard_lock_safe", "PASS")]
