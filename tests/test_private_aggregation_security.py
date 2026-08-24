"""Tests for PrivateAggregationSecurityScanner."""
from unittest.mock import MagicMock
from tblue.scanner.private_aggregation_security import PrivateAggregationSecurityScanner


def _scanner():
    s = PrivateAggregationSecurityScanner.__new__(PrivateAggregationSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestPIIInBucket:
    def test_pii_in_bucket_key_fails(self):
        s = _scanner()
        body = "privateAggregation.contributeToHistogram({bucket: hashOf(userId), value: 1})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "private_aggregation_pii_in_bucket" in types


class TestDebugMode:
    def test_debug_mode_in_production_warns(self):
        s = _scanner()
        body = "privateAggregation.enableDebugMode({debugKey: 1234n})\nprivateAggregation.contributeToHistogram({bucket: 1n, value: 128})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "private_aggregation_debug_mode" in types


class TestBucketFromParam:
    def test_bucket_from_url_param_fails(self):
        s = _scanner()
        body = "privateAggregation.contributeToHistogram({bucket: BigInt(searchParams.get('bucket')), value: 1})"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "private_aggregation_bucket_from_param" in types


class TestNotUsed:
    def test_no_private_aggregation_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "private_aggregation_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
