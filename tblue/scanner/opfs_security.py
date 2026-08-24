"""Origin Private File System (OPFS) security scanner — sensitive file writes, unauthorized read access."""
import re
from .base import BaseScanner

_OPFS_ANY_RE = re.compile(
    r'(?:navigator\.storage\.getDirectory\b|getDirectory\s*\(\s*\)|FileSystemSyncAccessHandle\b|createSyncAccessHandle\b)',
    re.I
)

# OPFS file write from URL parameter — attacker writes arbitrary content to OPFS
_OPFS_WRITE_FROM_PARAM_RE = re.compile(
    r'(?:getDirectory|FileSystem)[^;]{0,400}(?:write|writeFile|createWritable)[^;]{0,200}(?:searchParams|location\.search|getParam)',
    re.I | re.S
)

# Sensitive data written to OPFS — credentials stored in origin-private file
_OPFS_SENSITIVE_WRITE_RE = re.compile(
    r'(?:createWritable|write\s*\([^)]*|writeFile)[^;]{0,200}(?:token|password|apiKey|secret|sessionId|credential)',
    re.I | re.S
)

# OPFS file content transmitted to analytics
_OPFS_CONTENT_EXFIL_RE = re.compile(
    r'(?:getDirectory|FileSystemSyncAccessHandle)[^;]{0,400}(?:read|readFile|getFile)[^;]{0,200}(?:fetch|sendBeacon|XMLHttpRequest)',
    re.I | re.S
)

# OPFS directory listing transmitted — reveals which files exist in private storage
_OPFS_LISTING_EXFIL_RE = re.compile(
    r'(?:getDirectory|entries\s*\(\s*\))[^;]{0,300}(?:name|filename)[^;]{0,200}(?:fetch|sendBeacon|analytics)',
    re.I | re.S
)

# OPFS sync access handle used in main thread (should only be in workers)
_OPFS_SYNC_MAIN_THREAD_RE = re.compile(
    r'createSyncAccessHandle\s*\(\s*\)[^;]{0,200}(?:document\.|window\.|navigator\.)',
    re.I | re.S
)


class OPFSSecurityScanner(BaseScanner):
    def scan(self, url):
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "opfs_security", "PASS", detail="No response")]

        body = resp.text or ""

        if not _OPFS_ANY_RE.search(body):
            return [self._result(url, "opfs_not_used", "INFO",
                                 detail="Origin Private File System (OPFS) not detected")]

        results = []

        if _OPFS_WRITE_FROM_PARAM_RE.search(body):
            results.append(self._result(url, "opfs_write_from_url_param", "FAIL",
                                        detail="OPFS file content derived from URL parameter — attacker writes arbitrary data to origin-private filesystem via URL manipulation"))

        if _OPFS_SENSITIVE_WRITE_RE.search(body):
            results.append(self._result(url, "opfs_sensitive_data_written", "WARN",
                                        detail="Credentials/tokens written to OPFS — sensitive data persisted in origin-private filesystem (survives page refresh, accessible to all origin scripts)"))

        if _OPFS_CONTENT_EXFIL_RE.search(body):
            results.append(self._result(url, "opfs_file_content_exfiltrated", "FAIL",
                                        detail="OPFS file content read and transmitted to remote — origin-private file data exfiltrated"))

        if _OPFS_LISTING_EXFIL_RE.search(body):
            results.append(self._result(url, "opfs_directory_listing_exfiltrated", "WARN",
                                        detail="OPFS directory listing transmitted to remote — private file names revealed (may contain sensitive naming patterns)"))

        if _OPFS_SYNC_MAIN_THREAD_RE.search(body):
            results.append(self._result(url, "opfs_sync_handle_main_thread", "WARN",
                                        detail="FileSystemSyncAccessHandle used alongside main thread APIs — sync handles should only be used in Web Workers; misuse may indicate sandboxing bypass attempt"))

        if not results:
            results.append(self._result(url, "opfs_found_no_issues", "PASS",
                                        detail="OPFS usage appears safe"))

        return results
