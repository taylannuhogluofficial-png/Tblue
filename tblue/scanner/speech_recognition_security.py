"""Speech Recognition API security scanner — passive detection of audio surveillance."""
import re
from .base import BaseScanner

_SR_ANY_RE = re.compile(
    r'(?:new\s+SpeechRecognition\s*\(|new\s+webkitSpeechRecognition\s*\(|SpeechRecognitionEvent\b|\.onresult\s*=)',
    re.I,
)

_SR_AUTO_START_RE = re.compile(
    r'(?:DOMContentLoaded|pageshow)[^;]{0,300}(?:recognition|SpeechRecognition)[^;]{0,200}\.start\s*\(',
    re.I,
)

_SR_TRANSCRIPT_EXFIL_RE = re.compile(
    r'(?:recognition|SpeechRecognition)[^;]{0,300}transcript[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)

_SR_CONTINUOUS_RE = re.compile(
    r'(?:recognition|SpeechRecognition)[^;]{0,200}continuous\s*=\s*true[^;]{0,200}\.start\s*\(',
    re.I,
)

_SR_INTERIM_EXFIL_RE = re.compile(
    r'(?:interimTranscript|isFinal\s*===?\s*false)[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I,
)


class SpeechRecognitionSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "speech_recognition_not_used", "PASS")]

        body = resp.text

        if not _SR_ANY_RE.search(body):
            return [self._result(url, "speech_recognition_not_used", "PASS")]

        findings = []

        if _SR_AUTO_START_RE.search(body):
            findings.append(self._result(
                url, "speech_recognition_auto_start", "FAIL",
                detail="SpeechRecognition.start() triggered on page load — microphone activated without explicit user gesture.",
            ))

        if _SR_TRANSCRIPT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "speech_recognition_transcript_exfil", "FAIL",
                detail="Speech transcript transmitted to remote endpoint — audio-to-text surveillance via SpeechRecognition.",
            ))

        if _SR_CONTINUOUS_RE.search(body):
            findings.append(self._result(
                url, "speech_recognition_continuous_mode", "WARN",
                detail="SpeechRecognition runs in continuous mode — extended microphone surveillance session.",
            ))

        return findings or [self._result(url, "speech_recognition_safe", "PASS")]
