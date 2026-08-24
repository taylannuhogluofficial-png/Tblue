"""Handwriting Recognition API security scanner — passive detection of handwriting input surveillance."""
import re
from .base import BaseScanner

_HR_ANY_RE = re.compile(
    r'(?:navigator\.createHandwritingRecognizer\s*\(|HandwritingRecognizer\b|'
    r'HandwritingDrawing\b|HandwritingStroke\b|HandwritingPoint\b|'
    r'createHandwritingRecognizer\s*\(|getTextSegmentation\s*\()',
    re.I,
)

_HR_EXFIL_RE = re.compile(
    r'(?:HandwritingDrawing|HandwritingStroke|HandwritingRecognizer)\b[^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|WebSocket)',
    re.I,
)

_HR_LANGUAGE_FINGERPRINT_RE = re.compile(
    r'(?:HandwritingRecognizer|createHandwritingRecognizer)\b[^;]{0,300}'
    r'(?:languages|hints|recognitionType)[^;]{0,200}'
    r'(?:sendBeacon|fetch|analytics)',
    re.I,
)

_HR_PARAM_CONTROLLED_RE = re.compile(
    r'createHandwritingRecognizer\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_HR_CONTINUOUS_SURVEILLANCE_RE = re.compile(
    r'(?:HandwritingStroke|HandwritingPoint)\b[^;]{0,300}'
    r'(?:addEventListener|setInterval|requestAnimationFrame)[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)


class HandwritingRecognitionSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "handwriting_recognition_not_used", "PASS")]

        body = resp.text

        if not _HR_ANY_RE.search(body):
            return [self._result(url, "handwriting_recognition_not_used", "PASS")]

        findings = []

        if _HR_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "handwriting_recognition_data_exfil", "FAIL",
                detail="Handwriting recognition stroke/drawing data transmitted to remote — user handwriting input exfiltrated.",
            ))

        if _HR_LANGUAGE_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "handwriting_recognition_language_fingerprint", "WARN",
                detail="HandwritingRecognizer language/hint configuration transmitted — handwriting recognizer settings used for device fingerprinting.",
            ))

        if _HR_PARAM_CONTROLLED_RE.search(body):
            findings.append(self._result(
                url, "handwriting_recognition_param_controlled", "WARN",
                detail="createHandwritingRecognizer() configured from URL parameter — attacker-controlled handwriting recognizer setup.",
            ))

        if _HR_CONTINUOUS_SURVEILLANCE_RE.search(body):
            findings.append(self._result(
                url, "handwriting_recognition_continuous_surveillance", "FAIL",
                detail="HandwritingStroke/Point captured in continuous loop with network transmission — covert handwriting input surveillance.",
            ))

        return findings or [self._result(url, "handwriting_recognition_safe", "PASS")]
