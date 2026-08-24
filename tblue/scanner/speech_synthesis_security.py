"""Speech Synthesis API security scanner — passive detection of TTS misuse."""
import re
from .base import BaseScanner

_SS_ANY_RE = re.compile(
    r'(?:window\.speechSynthesis\b|SpeechSynthesisUtterance\b|speechSynthesis\.speak\b|getVoices\s*\(\s*\))',
    re.I,
)

_SS_VOICE_FINGERPRINT_RE = re.compile(
    r'getVoices\s*\(\s*\)[^;]{0,200}(?:fetch|sendBeacon|analytics|XMLHttpRequest)',
    re.I,
)

_SS_TEXT_FROM_PARAM_RE = re.compile(
    r'SpeechSynthesisUtterance\s*\([^)]*(?:searchParams|location\.hash|location\.href)[^)]*\)',
    re.I,
)

_SS_PHISHING_SPEAK_RE = re.compile(
    r'SpeechSynthesisUtterance\s*\([^)]*(?:password|enter your|click|verify|authorize)[^)]*\)',
    re.I,
)

_SS_RATE_EXFIL_RE = re.compile(
    r'SpeechSynthesisUtterance[^;]{0,200}(?:pitch|rate|volume)[^;]{0,200}(?:fetch|sendBeacon)',
    re.I,
)


class SpeechSynthesisSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "speech_synthesis_not_used", "PASS")]

        body = resp.text

        if not _SS_ANY_RE.search(body):
            return [self._result(url, "speech_synthesis_not_used", "PASS")]

        findings = []

        if _SS_VOICE_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "speech_synthesis_voice_fingerprinting", "WARN",
                detail="Speech synthesis voice list transmitted to analytics — TTS voice-based browser fingerprinting.",
            ))

        if _SS_TEXT_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "speech_synthesis_text_from_url_param", "FAIL",
                detail="SpeechSynthesisUtterance text sourced from URL parameter — attacker-controlled audio phishing message.",
            ))

        if _SS_PHISHING_SPEAK_RE.search(body):
            findings.append(self._result(
                url, "speech_synthesis_phishing_content", "WARN",
                detail="SpeechSynthesis speaks social engineering text (password/verify/authorize) — audio phishing via TTS.",
            ))

        return findings or [self._result(url, "speech_synthesis_safe", "PASS")]
