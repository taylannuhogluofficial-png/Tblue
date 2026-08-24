"""Tests for ZipSlipPassiveScanner."""
from unittest.mock import MagicMock
from tblue.scanner.zip_slip_passive import ZipSlipPassiveScanner


def _scanner():
    s = ZipSlipPassiveScanner.__new__(ZipSlipPassiveScanner)
    s.http = MagicMock()
    return s


def _resp(text="", status=200, headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = headers or {}
    return r


def test_extractall_no_path_check():
    s = _scanner()
    s.http.get.return_value = _resp(
        "with zipfile.ZipFile(uploaded_file) as zf: zf.extractall(path=extract_dir)"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "zip_slip_extractall_no_path_check" in types


def test_traversal_in_filename():
    s = _scanner()
    s.http.get.return_value = _resp(
        "zipfile.ZipFile: member name ../../../../var/www/html/shell.php found"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "zip_slip_traversal_in_filename" in types


def test_upload_extract_pattern():
    s = _scanner()
    s.http.get.return_value = _resp(
        "router.post('/upload', async (req, res) => { unzip(req.file.path, extractDir) })"
    )
    results = s.scan("http://example.com/upload")
    types = [r["type"] for r in results]
    assert "zip_slip_upload_extract_pattern" in types


def test_zip_slip_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>Regular page with no archive handling</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "zip_slip_not_used"
    assert results[0]["status"] == "PASS"


def test_zip_slip_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "zip_slip_not_used"
