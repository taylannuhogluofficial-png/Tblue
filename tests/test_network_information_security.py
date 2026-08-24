"""Tests for NetworkInformationSecurityScanner."""
import pytest
from unittest.mock import MagicMock
from tblue.scanner.network_information_security import NetworkInformationSecurityScanner


def _scanner():
    s = NetworkInformationSecurityScanner.__new__(NetworkInformationSecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestNetInfoTransmitted:
    def test_connection_data_sent_warns(self):
        s = _scanner()
        body = """
        const conn = navigator.connection;
        fetch('/api/log', {
            method: 'POST',
            body: JSON.stringify({ effectiveType: navigator.connection.effectiveType })
        });
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "net_info_transmitted_to_server" in types

    def test_beacon_with_downlink_warns(self):
        s = _scanner()
        body = "navigator.sendBeacon('/log', JSON.stringify({speed: navigator.connection.downlink}));"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "net_info_transmitted_to_server" in types


class TestAdaptivePayload:
    def test_dynamic_import_based_on_connection_warns(self):
        s = _scanner()
        body = """
        const conn = navigator.connection;
        if (conn.effectiveType === '4g') {
            import('./heavy-features.js');
        } else {
            require('./lite.js');
        }
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "net_info_adaptive_payload" in types


class TestThirdPartyTracking:
    def test_analytics_with_connection_warns(self):
        s = _scanner()
        body = "gtag('event', 'page_view', {connection: navigator.connection.effectiveType});"
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "net_info_shared_with_analytics" in types


class TestNotUsed:
    def test_no_network_info_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>No network API usage</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "net_info_not_used"
        assert results[0]["status"] == "PASS"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
