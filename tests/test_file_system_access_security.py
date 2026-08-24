"""Tests for FileSystemAccessSecurityScanner."""
import pytest
from unittest.mock import MagicMock
from tblue.scanner.file_system_access_security import FileSystemAccessSecurityScanner


def _scanner():
    s = FileSystemAccessSecurityScanner.__new__(FileSystemAccessSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestDirectoryPicker:
    def test_show_directory_picker_warns(self):
        s = _scanner()
        body = "const dirHandle = await showDirectoryPicker();"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "fsa_directory_picker" in types


class TestRecursiveDelete:
    def test_recursive_delete_fails(self):
        s = _scanner()
        body = """
        const fileHandle = await showOpenFilePicker();
        await entry.remove({ recursive: true });
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "fsa_recursive_delete" in types
        assert any(r["status"] == "FAIL" for r in results)


class TestHandlePersisted:
    def test_handle_in_local_storage_warns(self):
        s = _scanner()
        body = """
        const fileHandle = await showOpenFilePicker();
        localStorage.setItem('savedFile', JSON.stringify(fileHandle));
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "fsa_handle_persisted" in types


class TestSensitiveStartIn:
    def test_start_in_desktop_warns(self):
        s = _scanner()
        body = "const handle = await showOpenFilePicker({ startIn: 'desktop' });"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "fsa_sensitive_start_in" in types

    def test_start_in_downloads_passes(self):
        s = _scanner()
        body = "const handle = await showOpenFilePicker({ startIn: 'downloads' });"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "fsa_sensitive_start_in" not in types


class TestNotUsed:
    def test_no_fsa_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "fsa_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
