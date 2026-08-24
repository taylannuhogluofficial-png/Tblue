"""Tests for LockAPISecurityScanner."""
import pytest
from unittest.mock import MagicMock
from tblue.scanner.lock_api_security import LockAPISecurityScanner


def _scanner():
    s = LockAPISecurityScanner.__new__(LockAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestNoAbortSignal:
    def test_lock_without_signal_warns(self):
        s = _scanner()
        body = """
        await navigator.locks.request('my-lock', async (lock) => {
            await doWork();
        });
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "lock_api_no_abort_signal" in types

    def test_lock_with_signal_passes(self):
        s = _scanner()
        body = """
        const controller = new AbortController();
        await navigator.locks.request('my-lock', { signal: controller.signal }, async (lock) => {
            await doWork();
        });
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "lock_api_no_abort_signal" not in types


class TestStealTrue:
    def test_steal_true_warns(self):
        s = _scanner()
        body = """
        await navigator.locks.request('my-lock', { steal: true }, async (lock) => {
            await doWork();
        });
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "lock_api_steal_true" in types


class TestLockNameFromInput:
    def test_lock_name_from_url_param_warns(self):
        s = _scanner()
        body = "await navigator.locks.request(searchParams.get('key'), lock => doWork(lock));"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "lock_api_name_from_input" in types


class TestNotUsed:
    def test_no_lock_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "lock_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
