"""File Inclusion security scanner — detection of path traversal and file inclusion patterns."""
import re
from .base import BaseScanner

_FI_ANY_RE = re.compile(
    r'(?:readFile\s*\(|readFileSync\s*\(|'
    r'require\s*\(["\']\.{1,2}/|'
    r'include\s*\(|require_once\s*\(|'
    r'\.\./|path\.join\s*\()',
    re.I,
)

_FI_PATH_FROM_PARAM_RE = re.compile(
    r'(?:readFile|readFileSync|include|require_once)\s*\([^;]{0,200}'
    r'(?:searchParams|location\.hash|location\.href|userInput)',
    re.I,
)

_FI_PATH_TRAVERSAL_CONCAT_RE = re.compile(
    r'(?:path\.join|readFile|readFileSync)\s*\([^;]{0,200}'
    r'["\'\s]\s*\+\s*[^;]{0,200}'
    r'(?:userInput|filename|filepath|param)',
    re.I,
)

_FI_DOTDOT_IN_PARAM_RE = re.compile(
    r'(?:readFile|readFileSync|path\.join)\s*\([^;]{0,300}'
    r'(?:\.\./|%2e%2e|%252e%252e)',
    re.I,
)

_FI_FILE_CONTENT_EXFIL_RE = re.compile(
    r'(?:readFile|readFileSync)\s*\([^;]{0,400}'
    r'(?:sendBeacon|fetch\s*\([^)]{0,100}analytics|XMLHttpRequest)',
    re.I,
)


class FileInclusionSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "file_inclusion_not_used", "PASS")]

        body = resp.text
        if not _FI_ANY_RE.search(body):
            return [self._result(url, "file_inclusion_not_used", "PASS")]

        findings = []

        if _FI_PATH_FROM_PARAM_RE.search(body):
            findings.append(self._result(
                url, "file_inclusion_path_from_param", "FAIL",
                detail="readFile()/include() file path from URL parameter — attacker controls which file is read; classic LFI (local file inclusion) enabling /etc/passwd, config file access.",
            ))

        if _FI_PATH_TRAVERSAL_CONCAT_RE.search(body):
            findings.append(self._result(
                url, "file_inclusion_path_traversal_concat", "FAIL",
                detail="File path built via string concatenation with userInput/filename — path traversal via ../../ sequences in user-controlled filename enables reading arbitrary files.",
            ))

        if _FI_DOTDOT_IN_PARAM_RE.search(body):
            findings.append(self._result(
                url, "file_inclusion_dotdot_pattern", "FAIL",
                detail="readFile/path.join with ../ or URL-encoded %2e%2e — explicit path traversal sequence in file read operation enabling directory escape.",
            ))

        if _FI_FILE_CONTENT_EXFIL_RE.search(body):
            findings.append(self._result(
                url, "file_inclusion_content_exfil", "WARN",
                detail="File content from readFile() transmitted via fetch/sendBeacon — file contents exfiltrated to remote endpoint; combined with path traversal enables arbitrary file exfiltration.",
            ))

        return findings or [self._result(url, "file_inclusion_safe", "PASS")]
