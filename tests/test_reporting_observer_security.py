"""Tests for ReportingObserverSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.reporting_observer_security import ReportingObserverSecurityScanner


def _scanner():
    s = ReportingObserverSecurityScanner.__new__(ReportingObserverSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestDataExfil:
    def test_reports_exfiltrated_warns(self):
        s = _scanner()
        body = "const obs = new ReportingObserver(reports => { sendBeacon('/analytics', JSON.stringify(reports)) })\nobs.observe()"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "reporting_observer_data_exfil" in types


class TestPolicyProbe:
    def test_policy_probe_warns(self):
        s = _scanner()
        body = "new ReportingObserver(reports => { const blocked = reports.filter(r => r.type === 'feature-policy-violation')\nfetch('/probe', {body: JSON.stringify(blocked)}) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "reporting_observer_policy_probe" in types


class TestDeprecationProbe:
    def test_deprecation_probe_warns(self):
        s = _scanner()
        body = "new ReportingObserver(reports => { const deps = reports.filter(r => r.type === 'deprecation')\nanalytics('browser', {deps}) })"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "reporting_observer_deprecation_probe" in types


class TestNotUsed:
    def test_no_reporting_observer_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "reporting_observer_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
