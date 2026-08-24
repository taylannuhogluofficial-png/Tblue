"""Tests for FileInclusionSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.file_inclusion_security import FileInclusionSecurityScanner


def _scanner():
    s = FileInclusionSecurityScanner.__new__(FileInclusionSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_file_inclusion_path_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "readFile(searchParams.get('file'), 'utf8', callback)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "file_inclusion_path_from_param" in types


def test_file_inclusion_path_traversal_concat():
    s = _scanner()
    s.http.get.return_value = _resp(
        "readFile('/uploads/' + filename, 'utf8', cb)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "file_inclusion_path_traversal_concat" in types


def test_file_inclusion_dotdot_pattern():
    s = _scanner()
    s.http.get.return_value = _resp(
        "readFileSync(path.join('/var/www', '../../../etc/passwd'))"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "file_inclusion_dotdot_pattern" in types


def test_file_inclusion_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No file system access code here</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "file_inclusion_not_used"
    assert results[0]["status"] == "PASS"


def test_file_inclusion_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "file_inclusion_not_used"
