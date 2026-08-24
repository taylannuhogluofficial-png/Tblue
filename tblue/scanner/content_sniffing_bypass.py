"""Content Sniffing Bypass scanner — passive detection of MIME sniffing and content-type confusion vulnerabilities."""
import re
from .base import BaseScanner

_CS_ANY_RE = re.compile(
    r'(?:content-type|x-content-type-options|multipart/|'
    r'application/octet-stream|upload|filename\s*=)',
    re.I,
)

_CS_NOSNIFF_MISSING_RE = re.compile(
    r'content-type\s*:\s*(?:text/html|application/javascript|text/javascript)',
    re.I,
)

_CS_NOSNIFF_HEADER_RE = re.compile(
    r'x-content-type-options\s*:\s*nosniff',
    re.I,
)

_CS_WRONG_CONTENT_TYPE_RE = re.compile(
    r'content-type\s*:\s*(?:application/octet-stream|text/plain)\b',
    re.I,
)

_CS_SCRIPT_IN_BODY_RE = re.compile(
    r'<script\b[^>]*>.*?</script>|<html\b',
    re.I | re.S,
)

_CS_UPLOAD_REFLECTED_RE = re.compile(
    r'(?:filename|name)\s*=\s*["\'][^"\']{3,200}\.(?:html?|js|svg|xml|php)["\']',
    re.I,
)

_CS_MULTIPART_SNIFF_RE = re.compile(
    r'content-type\s*:\s*multipart/form-data[^\r\n]*\bboundary\b',
    re.I,
)

_CS_SVG_NO_NOSNIFF_RE = re.compile(
    r'content-type\s*:\s*image/svg\+xml',
    re.I,
)


class ContentSniffingBypassScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "content_sniffing_bypass_not_used", "PASS")]

        headers_str = ' '.join(f'{k}: {v}' for k, v in resp.headers.items())
        body = resp.text

        if not _CS_ANY_RE.search(headers_str) and not _CS_ANY_RE.search(body):
            return [self._result(url, "content_sniffing_bypass_not_used", "PASS")]

        findings = []
        has_nosniff = bool(_CS_NOSNIFF_HEADER_RE.search(headers_str))

        if _CS_NOSNIFF_MISSING_RE.search(headers_str) and not has_nosniff:
            findings.append(self._result(
                url, "content_sniffing_nosniff_missing", "WARN",
                detail="HTML or JavaScript content-type served without X-Content-Type-Options: nosniff — legacy browsers (IE/Edge) may sniff content type and execute attacker-supplied files as scripts.",
            ))

        if _CS_WRONG_CONTENT_TYPE_RE.search(headers_str) and _CS_SCRIPT_IN_BODY_RE.search(body):
            findings.append(self._result(
                url, "content_sniffing_script_in_octet_stream", "FAIL",
                detail="HTML/script content served with application/octet-stream or text/plain content-type — MIME sniffing browsers may execute as HTML; classic polyglot file attack vector.",
            ))

        if _CS_UPLOAD_REFLECTED_RE.search(body) and not has_nosniff:
            findings.append(self._result(
                url, "content_sniffing_upload_filename_reflected", "WARN",
                detail="Uploaded filename with executable extension (.html, .js, .svg, .php) reflected in response without nosniff — if file is served back, browser may execute it as the sniffed type.",
            ))

        if _CS_SVG_NO_NOSNIFF_RE.search(headers_str) and not has_nosniff:
            findings.append(self._result(
                url, "content_sniffing_svg_no_nosniff", "WARN",
                detail="SVG file served without X-Content-Type-Options: nosniff — SVG files can contain embedded JavaScript; browsers that execute inline SVG scripts bypass CSP script-src restrictions.",
            ))

        return findings or [self._result(url, "content_sniffing_bypass_safe", "PASS")]
