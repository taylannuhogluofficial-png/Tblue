"""Remote Playback API security scanner — passive detection of media casting misuse."""
import re
from .base import BaseScanner

_RP_ANY_RE = re.compile(
    r'(?:RemotePlayback\b|remote\.watchAvailability\s*\(|remote\.prompt\s*\(|'
    r'remote\.state\b|\.remote\b|disableRemotePlayback\b|'
    r'RemotePlaybackAvailabilityCallback\b)',
    re.I,
)

_RP_AUTO_CAST_RE = re.compile(
    r'remote\.prompt\s*\([^;]{0,300}'
    r'(?:DOMContentLoaded|onload|immediately|addEventListener)',
    re.I,
)

_RP_STATE_EXFIL_RE = re.compile(
    r'remote\.state\b[^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)

_RP_PARAM_CONTROLLED_RE = re.compile(
    r'(?:RemotePlayback|remote\.prompt)\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_RP_AVAILABILITY_SURVEILLANCE_RE = re.compile(
    r'watchAvailability\s*\([^;]{0,300}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I,
)


class RemotePlaybackSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "remote_playback_not_used", "PASS")]

        body = resp.text

        if not _RP_ANY_RE.search(body):
            return [self._result(url, "remote_playback_not_used", "PASS")]

        findings = []

        if _RP_AUTO_CAST_RE.search(body):
            findings.append(self._result(
                url, "remote_playback_auto_triggered", "WARN",
                detail="remote.prompt() triggered automatically on page load — unprompted remote device casting initiation.",
            ))

        if _RP_STATE_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "remote_playback_state_exfil", "WARN",
                detail="RemotePlayback state transmitted to remote analytics — cast device state used for user surveillance.",
            ))

        if _RP_PARAM_CONTROLLED_RE.search(body):
            findings.append(self._result(
                url, "remote_playback_param_controlled", "WARN",
                detail="Remote playback configured from URL parameter — attacker-controlled cast session parameters.",
            ))

        if _RP_AVAILABILITY_SURVEILLANCE_RE.search(body):
            findings.append(self._result(
                url, "remote_playback_availability_surveillance", "WARN",
                detail="watchAvailability() result transmitted to remote — casting device availability used to infer home network topology.",
            ))

        return findings or [self._result(url, "remote_playback_safe", "PASS")]
