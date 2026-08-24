"""Media Session API security scanner — playback metadata tracking, media title exfiltration."""
import re
from .base import BaseScanner

_MS_ANY_RE = re.compile(
    r'(?:navigator\.mediaSession\b|MediaSession\b|mediaSession\.metadata\b|MediaMetadata\b)',
    re.I
)

# Media metadata (title/artist/album) transmitted to analytics — media consumption tracking
_MS_METADATA_EXFIL_RE = re.compile(
    r'(?:mediaSession\.metadata|MediaMetadata)[^;]{0,300}(?:title|artist|album)[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I | re.S
)

# Media session action handler transmits playback position — detailed listening tracking
_MS_POSITION_EXFIL_RE = re.compile(
    r'(?:mediaSession\.setPositionState|positionState)[^;]{0,300}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I | re.S
)

# Media title/artist from URL parameter — attacker controls media metadata displayed in OS/browser
_MS_METADATA_FROM_PARAM_RE = re.compile(
    r'(?:new\s+MediaMetadata\s*\(|mediaSession\.metadata\s*=)[^;]{0,200}(?:searchParams|location\.search|getParam)',
    re.I | re.S
)

# Media action handler leaks track info via network request
_MS_ACTION_EXFIL_RE = re.compile(
    r'mediaSession\.setActionHandler\s*\([^)]*\)[^;]{0,400}(?:fetch|sendBeacon|XMLHttpRequest|analytics)',
    re.I | re.S
)

# Artwork URL from URL parameter — SSRF via media session album art
_MS_ARTWORK_SSRF_RE = re.compile(
    r'(?:new\s+MediaMetadata\s*\(|artwork)[^;]{0,300}(?:searchParams|location\.search|getParam)',
    re.I | re.S
)


class MediaSessionSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "media_session_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _MS_ANY_RE.search(body):
            return [self._result(url, "media_session_not_used", "INFO",
                                 detail="Media Session API not detected")]

        results = []

        if _MS_METADATA_EXFIL_RE.search(body):
            results.append(self._result(url, "media_session_metadata_exfiltrated", "WARN",
                                        detail="Media metadata (title/artist/album) transmitted to analytics — user media consumption profile exfiltrated"))

        if _MS_POSITION_EXFIL_RE.search(body):
            results.append(self._result(url, "media_session_position_tracked", "WARN",
                                        detail="Media playback position transmitted to remote — detailed listening/viewing timeline exfiltrated"))

        if _MS_METADATA_FROM_PARAM_RE.search(body):
            results.append(self._result(url, "media_session_metadata_from_url_param", "WARN",
                                        detail="MediaMetadata content derived from URL parameter — attacker controls track title/artist shown in OS lock screen or browser media UI"))

        if _MS_ARTWORK_SSRF_RE.search(body):
            results.append(self._result(url, "media_session_artwork_ssrf", "WARN",
                                        detail="Media artwork URL from URL parameter — attacker controls image URL fetched for media session (SSRF via album art)"))

        if _MS_ACTION_EXFIL_RE.search(body):
            results.append(self._result(url, "media_session_action_exfiltrated", "WARN",
                                        detail="Media session action handler makes network request — user play/pause/skip actions tracked and transmitted"))

        if not results:
            results.append(self._result(url, "media_session_found_no_issues", "PASS",
                                        detail="Media Session API usage appears safe"))

        return results
