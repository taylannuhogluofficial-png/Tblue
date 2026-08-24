"""Web Audio API security scanner — AudioContext fingerprinting, audio data exfiltration, mic access."""
import re
from .base import BaseScanner

_WA_CONTEXT_RE  = re.compile(r'new\s+(?:AudioContext|OfflineAudioContext)\s*\(', re.I)
_WA_ANY_RE      = re.compile(
    r'(?:AudioContext|OfflineAudioContext|AudioWorklet|AnalyserNode|AudioBuffer|createMediaStreamSource)\b',
    re.I
)

# AudioContext fingerprinting — extracting hardware characteristics
_WA_FINGERPRINT_RE = re.compile(
    r'(?:sampleRate|maxChannelCount|numberOfInputs|numberOfOutputs|channelCount)[^;]{0,200}'
    r'(?:fetch|XMLHttpRequest|sendBeacon|analytics)',
    re.I | re.S
)

# AnalyserNode data transmitted
_WA_ANALYSER_SEND_RE = re.compile(
    r'(?:AnalyserNode|getByteFrequencyData|getFloatFrequencyData|getByteTimeDomainData)[^;]{0,300}'
    r'(?:fetch|XMLHttpRequest|sendBeacon)',
    re.I | re.S
)

# Microphone connected to AudioContext (capture without visible indication)
_WA_MIC_CONNECT_RE = re.compile(
    r'(?:getUserMedia|mediaDevices)[^;]{0,300}(?:AudioContext|createMediaStreamSource)', re.I | re.S
)

# AudioBuffer transmitted — raw audio data exfiltration
_WA_BUFFER_SEND_RE = re.compile(
    r'(?:AudioBuffer|getChannelData|copyFromChannel)[^;]{0,200}(?:fetch|XMLHttpRequest|sendBeacon)',
    re.I | re.S
)

# Oscillator/gain used for audio steganography pattern
_WA_STEGO_RE = re.compile(
    r'(?:OscillatorNode|createOscillator)[^;]{0,300}(?:cookie|token|localStorage|sessionStorage)',
    re.I | re.S
)


class WebAudioSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "web_audio_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _WA_ANY_RE.search(body):
            return [self._result(url, "web_audio_not_used", "INFO",
                                 detail="Web Audio API not detected")]

        results = []

        if _WA_FINGERPRINT_RE.search(body):
            results.append(self._result(url, "web_audio_fingerprinting", "WARN",
                                        detail="AudioContext hardware properties transmitted — audio device fingerprinting"))

        if _WA_MIC_CONNECT_RE.search(body):
            results.append(self._result(url, "web_audio_microphone_processing", "WARN",
                                        detail="Microphone stream connected to AudioContext — covert audio analysis possible"))

        if _WA_ANALYSER_SEND_RE.search(body):
            results.append(self._result(url, "web_audio_analyser_data_transmitted", "WARN",
                                        detail="AnalyserNode frequency/time-domain data transmitted — audio content fingerprinting"))

        if _WA_BUFFER_SEND_RE.search(body):
            results.append(self._result(url, "web_audio_buffer_transmitted", "FAIL",
                                        detail="AudioBuffer channel data transmitted — raw audio sample exfiltration"))

        if _WA_STEGO_RE.search(body):
            results.append(self._result(url, "web_audio_steganography_pattern", "WARN",
                                        detail="Oscillator with sensitive data context — potential audio steganography covert channel"))

        if not results:
            results.append(self._result(url, "web_audio_found_no_issues", "PASS",
                                        detail="Web Audio API usage appears safe"))

        return results
