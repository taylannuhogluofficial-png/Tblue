"""Media Devices security scanner — passive detection of camera/microphone access misuse."""
import re
from .base import BaseScanner

_MD_ANY_RE = re.compile(
    r'(?:navigator\.mediaDevices\b|getUserMedia\s*\(|'
    r'getDisplayMedia\s*\(|enumerateDevices\s*\(|'
    r'MediaStream\b|MediaStreamTrack\b|'
    r'RTCPeerConnection\b)',
    re.I,
)

_MD_STREAM_EXFIL_RE = re.compile(
    r'getUserMedia\s*\([^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|WebSocket|RTCPeerConnection)',
    re.I,
)

_MD_ENUMERATE_EXFIL_RE = re.compile(
    r'enumerateDevices\s*\([^;]{0,400}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_MD_FROM_PARAM_RE = re.compile(
    r'getUserMedia\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_MD_TRACK_LABEL_EXFIL_RE = re.compile(
    r'(?:\.label\b|deviceId\b)[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class MediaDevicesSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "media_devices_not_used", "PASS")]

        body = resp.text

        if not _MD_ANY_RE.search(body):
            return [self._result(url, "media_devices_not_used", "PASS")]

        findings = []

        if _MD_STREAM_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "media_devices_stream_exfil", "FAIL",
                detail="getUserMedia() stream sent via RTCPeerConnection/WebSocket/fetch — camera/microphone stream captured and transmitted to remote (covert surveillance).",
            ))

        if _MD_ENUMERATE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "media_devices_enumerate_exfil", "WARN",
                detail="enumerateDevices() result transmitted to analytics — device list (cameras, microphones, speakers) exfiltrated for cross-site hardware fingerprinting.",
            ))

        if _MD_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "media_devices_constraints_from_param", "WARN",
                detail="getUserMedia() constraints from URL parameter — attacker-controlled media constraints (resolution, deviceId) for targeted capture configuration.",
            ))

        if _MD_TRACK_LABEL_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "media_devices_label_exfil", "WARN",
                detail="MediaStreamTrack.label/deviceId transmitted to remote — device identifiers exfiltrated for persistent cross-site user tracking.",
            ))

        return findings or [self._result(url, "media_devices_safe", "PASS")]
