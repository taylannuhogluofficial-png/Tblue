"""Web MIDI API security scanner — SysEx injection, device enumeration fingerprinting, data exfiltration."""
import re
from .base import BaseScanner

_MIDI_ACCESS_RE = re.compile(r'navigator\.requestMIDIAccess\s*\(', re.I)
_MIDI_ANY_RE    = re.compile(r'(?:requestMIDIAccess|MIDIAccess|MIDIInput|MIDIOutput|MIDIMessageEvent)\b', re.I)

# SysEx enabled (dangerous — firmware/device control)
_MIDI_SYSEX_RE = re.compile(r'requestMIDIAccess\s*\(\s*\{[^}]*sysex\s*:\s*true', re.I | re.S)

# SysEx data from URL param — attacker controlled MIDI command
_MIDI_SYSEX_URL_RE = re.compile(
    r'(?:send|output\.send)\s*\([^)]*(?:location\.|searchParams|getParam)', re.I | re.S
)

# MIDI device info transmitted (fingerprinting)
_MIDI_DEVICE_SEND_RE = re.compile(
    r'(?:name|manufacturer|version|id)[^;]{0,200}(?:fetch|XMLHttpRequest|sendBeacon)',
    re.I | re.S
)

# MIDI message data to analytics
_MIDI_ANALYTICS_RE = re.compile(
    r'(?:gtag|analytics|fbq|mixpanel)[^;]{0,200}(?:midi|MIDIAccess|MIDIInput)', re.I | re.S
)

# All inputs/outputs enumerated (device fingerprinting)
_MIDI_ENUM_RE = re.compile(r'(?:inputs|outputs)\.forEach\s*\(', re.I)


class MIDIAPISecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "midi_api_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _MIDI_ANY_RE.search(body):
            return [self._result(url, "midi_api_not_used", "INFO",
                                 detail="Web MIDI API not detected")]

        results = []

        if _MIDI_SYSEX_RE.search(body):
            results.append(self._result(url, "midi_sysex_enabled", "FAIL",
                                        detail="sysex:true requested — SysEx allows sending arbitrary firmware/control commands to MIDI hardware"))

        if _MIDI_SYSEX_URL_RE.search(body):
            results.append(self._result(url, "midi_sysex_from_url_param", "FAIL",
                                        detail="MIDI send() with URL parameter data — attacker-controlled MIDI command injection"))

        if _MIDI_ENUM_RE.search(body):
            results.append(self._result(url, "midi_device_enumeration", "WARN",
                                        detail="All MIDI inputs/outputs enumerated — connected MIDI device list fingerprints the user"))

        if _MIDI_DEVICE_SEND_RE.search(body):
            results.append(self._result(url, "midi_device_info_transmitted", "WARN",
                                        detail="MIDI device name/manufacturer transmitted — hardware fingerprinting"))

        if _MIDI_ANALYTICS_RE.search(body):
            results.append(self._result(url, "midi_data_to_analytics", "WARN",
                                        detail="MIDI device or message data shared with analytics"))

        if not results:
            results.append(self._result(url, "midi_api_found_no_issues", "PASS",
                                        detail="Web MIDI API usage appears safe"))

        return results
