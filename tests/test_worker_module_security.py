"""Tests for WorkerModuleSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.worker_module_security import WorkerModuleSecurityScanner


def _scanner():
    s = WorkerModuleSecurityScanner.__new__(WorkerModuleSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(text, status=200):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.headers = {}
    return r


def test_worker_module_url_from_param():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const w = new Worker(searchParams.get('worker'), {type: 'module'})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "worker_module_url_from_param" in types


def test_worker_module_external_url():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const w = new Worker('https://cdn.evil.com/worker.js', {type: 'module'})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "worker_module_external_url" in types


def test_worker_postmessage_sensitive_data():
    s = _scanner()
    s.http.get.return_value = _resp(
        "const w = new Worker('/worker.js')\n"
        "worker.postMessage({token: localStorage.getItem('auth'), password: userPwd})"
    )
    results = s.scan("http://example.com")
    types = [r["type"] for r in results]
    assert "worker_postmessage_sensitive_data" in types


def test_worker_module_not_used():
    s = _scanner()
    s.http.get.return_value = _resp("<html>No workers</html>")
    results = s.scan("http://example.com")
    assert results[0]["type"] == "worker_module_not_used"
    assert results[0]["status"] == "PASS"


def test_worker_module_null_response():
    s = _scanner()
    s.http.get.return_value = None
    results = s.scan("http://example.com")
    assert results[0]["type"] == "worker_module_not_used"
