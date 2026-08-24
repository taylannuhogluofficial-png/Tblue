"""Tests for AttributionReportingSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.attribution_reporting_security import AttributionReportingSecurityScanner


def _scanner():
    s = AttributionReportingSecurityScanner.__new__(AttributionReportingSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestPIIInSource:
    def test_pii_in_source_registration_fails(self):
        s = _scanner()
        body = "img.attributionsrc = '/register?userId=' + user.email + '&source=ad'"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "attribution_source_contains_pii" in types


class TestCrossOriginDest:
    def test_cross_origin_destination_warns(self):
        s = _scanner()
        body = 'Attribution-Reporting-Register-Source: {"attributionDestination": "https://tracker.example.com", "source_event_id": "123"}'
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "attribution_cross_origin_destination" in types


class TestFilterDataPII:
    def test_filter_data_pii_fails(self):
        s = _scanner()
        body = 'registerSource({filterData: {userId: "abc123", email: "user@example.com"}, attributionDestination: "https://example.com"})'
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "attribution_filter_data_contains_pii" in types


class TestNotUsed:
    def test_no_attribution_reporting_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "attribution_reporting_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
