"""Media Source Extensions (MSE) security — untrusted video sources, arbitrary codec injection, MIME spoofing."""
import re
from .base import BaseScanner

_MSE_MEDIA_SOURCE_RE = re.compile(r'new\s+MediaSource\s*\(\s*\)', re.I)
_MSE_OPEN_RE = re.compile(r'MediaSource\.isTypeSupported\s*\(|\.addSourceBuffer\s*\(', re.I)
_MSE_URL_FROM_PARAM_RE = re.compile(
    r'URL\.createObjectURL\s*\([^)]*\)[^;]{0,100}(?:video|audio|src)\s*=',
    re.I | re.S,
)
_MSE_URL_PARAM_SOURCE_RE = re.compile(
    r'(?:fetch|XMLHttpRequest)\s*\([^)]*(?:location\.|searchParams|getParam)[^)]*\)[^;]{0,200}addSourceBuffer',
    re.I | re.S,
)
_MSE_MIME_NO_VALIDATION_RE = re.compile(
    r'addSourceBuffer\s*\(\s*(?:location\.|searchParams|getParam|mimeType)',
    re.I,
)
_MSE_CLEARTEXT_FETCH_RE = re.compile(
    r'fetch\s*\(\s*["\']http://',
    re.I,
)
_MSE_EME_RE = re.compile(r'navigator\.requestMediaKeySystemAccess\s*\(', re.I)
_MSE_EME_INSECURE_RE = re.compile(
    r'requestMediaKeySystemAccess\s*\([^)]*["\'](?:org\.w3\.clearkey)["\']',
    re.I,
)


class MediaSourceExtensionSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "mse_no_response", "PASS", detail="No response")]

        body = resp.text or ""

        if not _MSE_MEDIA_SOURCE_RE.search(body) and not _MSE_OPEN_RE.search(body):
            return [self._result(url, "mse_not_used", "PASS",
                                 detail="Media Source Extensions not detected on this page")]

        if _MSE_URL_PARAM_SOURCE_RE.search(body):
            results.append(self._result(url, "mse_source_from_url_param", "FAIL",
                                        detail="Media source buffer constructed from URL parameter — "
                                               "attacker controls video/audio source URL via URL manipulation; "
                                               "can inject malicious media that exploits codec parsing vulnerabilities"))

        if _MSE_MIME_NO_VALIDATION_RE.search(body):
            results.append(self._result(url, "mse_mime_from_url_param", "WARN",
                                        detail="addSourceBuffer() MIME type derived from URL parameter — "
                                               "attacker can specify arbitrary codec MIME type, potentially crashing browser codec handlers"))

        if _MSE_EME_INSECURE_RE.search(body):
            results.append(self._result(url, "mse_clearkey_drm", "WARN",
                                        detail="Encrypted Media Extensions using org.w3.clearkey — "
                                               "ClearKey is a test/debug DRM system with no real content protection; "
                                               "use commercial DRM (Widevine/FairPlay) for protected content"))

        if _MSE_CLEARTEXT_FETCH_RE.search(body) and _MSE_MEDIA_SOURCE_RE.search(body):
            results.append(self._result(url, "mse_cleartext_media_fetch", "WARN",
                                        detail="Media content fetched over HTTP for MSE — "
                                               "video/audio segments downloadable by MITM; "
                                               "use HTTPS for all media manifest and segment URLs"))

        if not results:
            results.append(self._result(url, "mse_found_no_issues", "PASS",
                                        detail="Media Source Extensions in use but no security issues detected"))
        return results
