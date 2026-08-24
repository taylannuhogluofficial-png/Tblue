"""Tests for SchedulerAPISecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.scheduler_api_security import SchedulerAPISecurityScanner


def _scanner():
    s = SchedulerAPISecurityScanner.__new__(SchedulerAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestDataExfil:
    def test_task_data_exfiltrated_fails(self):
        s = _scanner()
        # _SCHED_DATA_EXFIL_RE: scheduler.postTask ... fetch ... localStorage
        body = "scheduler.postTask(() => fetch('/upload', {body: localStorage.getItem('token')}))"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "scheduler_task_data_exfiltrated" in types


class TestSensitiveTask:
    def test_sensitive_data_in_task_warns(self):
        s = _scanner()
        # _SCHED_SENSITIVE_TASK_RE: scheduler.postTask ... apiKey
        body = "scheduler.postTask(() => { init(apiKey) }, {priority: 'user-blocking'})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "scheduler_sensitive_data_in_task" in types


class TestAbortFromParam:
    def test_abort_from_url_param_warns(self):
        s = _scanner()
        # _SCHED_ABORT_FROM_PARAM_RE: TaskController ... searchParams ... abort()
        body = "const ctrl = new TaskController()\nif (searchParams.get('stop')) { ctrl.abort() }"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "scheduler_abort_from_url_param" in types


class TestNotUsed:
    def test_no_scheduler_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "scheduler_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
