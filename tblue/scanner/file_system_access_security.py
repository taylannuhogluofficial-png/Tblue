"""File System Access API security — excessive directory scope, persisting sensitive paths, lack of user gesture."""
import re
from .base import BaseScanner

_FSA_SHOW_OPEN_RE = re.compile(r'(?:window\.)?showOpenFilePicker\s*\(', re.I)
_FSA_SHOW_SAVE_RE = re.compile(r'(?:window\.)?showSaveFilePicker\s*\(', re.I)
_FSA_SHOW_DIR_RE = re.compile(r'(?:window\.)?showDirectoryPicker\s*\(', re.I)
_FSA_GET_DIR_RE = re.compile(r'navigator\.storage\.getDirectory\s*\(', re.I)

_FSA_SENSITIVE_PATH_RE = re.compile(
    r'(?:startIn|suggestedName)\s*:\s*["\'](?:desktop|documents|home|root|/)',
    re.I,
)

_FSA_WRITABLE_RE = re.compile(r'createWritable\s*\(\s*\)', re.I)
_FSA_REMOVE_RE = re.compile(r'\.remove\s*\(\s*\{[^}]*recursive\s*:\s*true', re.I)

_FSA_PERSIST_HANDLE_RE = re.compile(
    r'(?:localStorage|sessionStorage|indexedDB|caches)\.(?:setItem|put|open)[^;]{0,200}FileHandle',
    re.I | re.S,
)

_FSA_PATH_SEND_RE = re.compile(
    r'(?:fetch|XMLHttpRequest|axios)\s*\([^)]*(?:\.name|\.relativePath|fileHandle)',
    re.I,
)

_FSA_NO_GESTURE_RE = re.compile(
    r'(?:async\s+)?function\s+\w*(?:init|load|start|boot|auto)\w*[^{]*\{[^}]*showOpenFilePicker',
    re.I | re.S,
)


class FileSystemAccessSecurityScanner(BaseScanner):
    def scan(self, url: str) -> list:
        results = []
        resp = self.http.get(url)
        if resp is None:
            return [self._result(url, "fsa_no_response", "PASS", detail="No response")]

        body = resp.text or ""

        uses_fsa = bool(
            _FSA_SHOW_OPEN_RE.search(body) or _FSA_SHOW_DIR_RE.search(body) or
            _FSA_SHOW_SAVE_RE.search(body) or _FSA_GET_DIR_RE.search(body)
        )

        if not uses_fsa:
            return [self._result(url, "fsa_not_used", "PASS",
                                 detail="File System Access API not detected on this page")]

        if _FSA_SHOW_DIR_RE.search(body):
            results.append(self._result(url, "fsa_directory_picker", "WARN",
                                        detail="showDirectoryPicker() grants full directory read/write access — "
                                               "broadest File System Access scope; verify user understands they are "
                                               "granting access to all files in the selected directory"))

        if _FSA_REMOVE_RE.search(body):
            results.append(self._result(url, "fsa_recursive_delete", "FAIL",
                                        detail="FileSystemEntry.remove({recursive: true}) can delete entire directory trees — "
                                               "irreversible destructive operation; confirm explicit user intent before executing"))

        if _FSA_PERSIST_HANDLE_RE.search(body):
            results.append(self._result(url, "fsa_handle_persisted", "WARN",
                                        detail="FileSystemFileHandle persisted in localStorage/IndexedDB — "
                                               "stored handles grant persistent file system access; "
                                               "XSS attacker can read stored handles and access user's files without new picker"))

        if _FSA_PATH_SEND_RE.search(body):
            results.append(self._result(url, "fsa_path_transmitted", "WARN",
                                        detail="File path/name sent to server — "
                                               "file paths reveal local directory structure and file naming conventions; "
                                               "transmit only file contents, not file system paths"))

        if _FSA_SENSITIVE_PATH_RE.search(body):
            results.append(self._result(url, "fsa_sensitive_start_in", "WARN",
                                        detail="File picker configured with startIn:'desktop'/'documents'/'home' — "
                                               "starting in sensitive directories guides users to share personal files; "
                                               "use task-specific suggestions instead of broad OS directories"))

        if not results:
            results.append(self._result(url, "fsa_found_no_issues", "PASS",
                                        detail="File System Access API in use but no security issues detected"))
        return results
