"""MediaCapabilities API security scanner — passive detection of capability-based device fingerprinting."""
import re
from .base import BaseScanner

_MC_ANY_RE = re.compile(
    r'(?:navigator\.mediaCapabilities\b|mediaCapabilities\.decodingInfo\s*\(|'
    r'mediaCapabilities\.encodingInfo\s*\(|MediaCapabilitiesInfo\b|decodingInfo\b|encodingInfo\b)',
    re.I,
)

_MC_FINGERPRINT_RE = re.compile(
    r'(?:decodingInfo|encodingInfo)\b[^;]{0,300}'
    r'(?:sendBeacon|fetch|XMLHttpRequest|analytics)[^;]{0,200}'
    r'(?:fingerprint|fp|deviceId|supported|smooth|powerEfficient)',
    re.I,
)

_MC_BATCH_PROBE_RE = re.compile(
    r'(?:decodingInfo|encodingInfo)\b[^;]{0,200}'
    r'(?:forEach|map|Promise\.all)[^;]{0,200}'
    r'(?:sendBeacon|fetch|XMLHttpRequest)',
    re.I,
)

_MC_PARAM_CONTROLLED_RE = re.compile(
    r'(?:decodingInfo|encodingInfo)\b[^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href)',
    re.I,
)

_MC_COVERT_CHANNEL_RE = re.compile(
    r'(?:smooth|powerEfficient|supported)\b[^;]{0,200}'
    r'(?:fetch|sendBeacon|XMLHttpRequest|postMessage)',
    re.I,
)


class MediaCapabilitiesSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "media_capabilities_not_used", "PASS")]

        body = resp.text

        if not _MC_ANY_RE.search(body):
            return [self._result(url, "media_capabilities_not_used", "PASS")]

        findings = []

        if _MC_FINGERPRINT_RE.search(body):
            findings.append(self._result(
                url, "media_capabilities_fingerprinting", "FAIL",
                detail="MediaCapabilities decode/encode results transmitted for fingerprinting — codec support used as device identifier.",
            ))

        if _MC_BATCH_PROBE_RE.search(body):
            findings.append(self._result(
                url, "media_capabilities_batch_probe", "WARN",
                detail="Multiple MediaCapabilities probes batched and transmitted — systematic codec enumeration for device profiling.",
            ))

        if _MC_PARAM_CONTROLLED_RE.search(body):
            findings.append(self._result(
                url, "media_capabilities_param_controlled", "WARN",
                detail="MediaCapabilities query configured from URL parameter — attacker-controlled codec probe parameters.",
            ))

        if _MC_COVERT_CHANNEL_RE.search(body):
            findings.append(self._result(
                url, "media_capabilities_covert_channel", "WARN",
                detail="smooth/powerEfficient/supported codec flags transmitted remotely — hardware decoder state used as covert channel.",
            ))

        return findings or [self._result(url, "media_capabilities_safe", "PASS")]
