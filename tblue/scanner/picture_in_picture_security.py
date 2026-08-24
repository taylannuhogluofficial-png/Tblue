"""Picture-in-Picture API security scanner — passive detection of PiP API misuse."""
import re
from .base import BaseScanner

_PIP_ANY_RE = re.compile(
    r'(?:requestPictureInPicture\s*\(|document\.pictureInPictureElement\b|'
    r'enterpictureinpicture\b|leavepictureinpicture\b|PictureInPictureWindow\b)',
    re.I,
)

_PIP_AUTO_ENTER_RE = re.compile(
    r'(?:DOMContentLoaded|pageshow|load)[^;]{0,300}requestPictureInPicture\s*\('
    r'|requestPictureInPicture\s*\([^)]*\)[^;]{0,100}(?:DOMContentLoaded|pageshow)',
    re.I,
)

_PIP_TRACK_EXFIL_RE = re.compile(
    r'(?:enterpictureinpicture|PictureInPictureWindow)[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_PIP_SIZE_FINGERPRINT_RE = re.compile(
    r'PictureInPictureWindow[^;]{0,200}(?:width|height)[^;]{0,200}'
    r'(?:fetch|sendBeacon|analytics)',
    re.I,
)

_PIP_PARAM_CONTROLLED_RE = re.compile(
    r'requestPictureInPicture\s*\([^)]*(?:searchParams|location\.hash|location\.href)[^)]*\)',
    re.I,
)


class PictureInPictureSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "pip_not_used", "PASS")]

        body = resp.text

        if not _PIP_ANY_RE.search(body):
            return [self._result(url, "pip_not_used", "PASS")]

        findings = []

        if _PIP_AUTO_ENTER_RE.search(body):
            findings.append(self._result(
                url, "pip_auto_enter_on_load", "WARN",
                detail="requestPictureInPicture() triggered on page load — unsolicited PiP window without user gesture.",
            ))

        if _PIP_TRACK_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "pip_state_exfiltrated", "WARN",
                detail="PiP enter/leave events transmitted to remote — user media viewing behaviour surveillance.",
            ))

        if _PIP_SIZE_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "pip_window_size_fingerprinting", "WARN",
                detail="PictureInPictureWindow dimensions transmitted to remote — screen/viewport fingerprinting via PiP.",
            ))

        if _PIP_PARAM_CONTROLLED_RE.search(body):
            findings.append(self._result(
                url, "pip_url_param_controlled", "FAIL",
                detail="requestPictureInPicture() called with URL parameter — attacker-controlled PiP target.",
            ))

        return findings or [self._result(url, "pip_safe", "PASS")]
