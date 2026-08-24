"""Zip Slip Passive scanner — passive detection of path traversal in archive extraction."""
import re
from .base import BaseScanner

_ZS_ANY_RE = re.compile(
    r'(?:\.zip|\.tar|\.gz|\.tgz|\.jar|\.war|\.rar|'
    r'ZipFile|ZipInputStream|TarFile|zipfile\.|tarfile\.|'
    r'extractall|extract\s*\(|unzip|decompress)',
    re.I,
)

_ZS_EXTRACTALL_NO_CHECK_RE = re.compile(
    r'(?:\.extractall\s*\(\s*(?:path|dest|target|directory)|'
    r'zipfile\.ZipFile[^;]{0,200}\.extractall|'
    r'tarfile\.open[^;]{0,200}\.extractall)',
    re.I,
)

_ZS_NO_PATH_CHECK_BEFORE_EXTRACT_RE = re.compile(
    r'for\s+\w+\s+in\s+(?:\w+\.(?:namelist|getnames|infolist))\s*\(\s*\)'
    r'(?![\s\S]{0,500}(?:startswith|abspath|realpath|normpath|resolve))',
    re.I | re.S,
)

_ZS_TRAVERSAL_IN_FILENAME_RE = re.compile(
    r'(?:\.\./|\.\.\\)[^"\'<>\s]{0,100}\.(?:py|php|js|sh|rb|pl|exe|dll|so)',
    re.I,
)

_ZS_JAVA_EXTRACT_NO_CHECK_RE = re.compile(
    r'(?:ZipInputStream|ZipFile)[^;]{0,300}'
    r'getInputStream\s*\([^)]{0,100}\)'
    r'(?![\s\S]{0,300}(?:canonicalPath|normalize|startsWith))',
    re.I | re.S,
)

_ZS_UPLOAD_THEN_EXTRACT_RE = re.compile(
    r'(?:multipart|upload|form-data)[^;]{0,200}'
    r'(?:extract|unzip|decompress|ZipFile|tarfile)',
    re.I,
)

_ZS_OVERWRITE_DETECTION_RE = re.compile(
    r'(?:member\.name|entry\.name|info\.filename|zipinfo\.filename)'
    r'[^;]{0,200}(?:os\.path\.join|open\s*\(|write\s*\()',
    re.I,
)


class ZipSlipPassiveScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "zip_slip_not_used", "PASS")]

        body = resp.text
        if not _ZS_ANY_RE.search(body):
            return [self._result(url, "zip_slip_not_used", "PASS")]

        findings = []

        if _ZS_EXTRACTALL_NO_CHECK_RE.search(body):
            findings.append(self._result(
                url, "zip_slip_extractall_no_path_check", "FAIL",
                detail="ZipFile/TarFile.extractall() called with destination path — extractall() does not sanitize archive member paths; a crafted archive with ../../../../etc/cron.d/backdoor as filename writes files anywhere on the filesystem with server process privileges.",
            ))

        if _ZS_NO_PATH_CHECK_BEFORE_EXTRACT_RE.search(body):
            findings.append(self._result(
                url, "zip_slip_iteration_no_path_validation", "FAIL",
                detail="Iterating archive members without path normalization/canonicalization check — each member's filename must be resolved against the extraction root and verified to stay within it; missing check allows ../ sequences to escape.",
            ))

        if _ZS_TRAVERSAL_IN_FILENAME_RE.search(body):
            findings.append(self._result(
                url, "zip_slip_traversal_in_filename", "FAIL",
                detail="../ path traversal sequence with executable extension in archive filename — attacker-crafted archive contains malicious path that writes executable files (PHP, Python, shell scripts) to web root or system directories.",
            ))

        if _ZS_JAVA_EXTRACT_NO_CHECK_RE.search(body):
            findings.append(self._result(
                url, "zip_slip_java_zipinputstream_no_check", "FAIL",
                detail="Java ZipInputStream/ZipFile extraction without canonicalPath or normalize validation — Java Zip Slip; attacker archive writes WebShell to servlet container webapps/ directory or overwrites system configuration files.",
            ))

        if _ZS_UPLOAD_THEN_EXTRACT_RE.search(body):
            findings.append(self._result(
                url, "zip_slip_upload_extract_pattern", "WARN",
                detail="File upload combined with archive extraction in the same code path — user-supplied archive is extracted server-side; without path validation this is the classic Zip Slip attack vector; archive contents must be validated before any file is written.",
            ))

        if _ZS_OVERWRITE_DETECTION_RE.search(body):
            findings.append(self._result(
                url, "zip_slip_member_name_direct_write", "WARN",
                detail="Archive member filename (member.name, entry.name, info.filename) used directly in os.path.join() or open() — member filename must be sanitized before use as filesystem path; direct use enables path traversal to arbitrary write locations.",
            ))

        return findings or [self._result(url, "zip_slip_safe", "PASS")]
