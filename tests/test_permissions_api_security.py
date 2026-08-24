"""Tests for PermissionsAPISecurityScanner."""
import pytest
from unittest.mock import MagicMock
from tblue.scanner.permissions_api_security import PermissionsAPISecurityScanner


def _scanner():
    s = PermissionsAPISecurityScanner.__new__(PermissionsAPISecurityScanner)
    s.http = MagicMock()
    return s


def _resp(status=200, body="", headers=None):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = headers or {}
    return r


class TestBulkEnumeration:
    def test_bulk_permission_query_warns(self):
        s = _scanner()
        body = """
        navigator.permissions.query({name: 'camera'});
        navigator.permissions.query({name: 'microphone'});
        navigator.permissions.query({name: 'geolocation'});
        navigator.permissions.query({name: 'notifications'});
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "permissions_api_bulk_enumeration" in types

    def test_single_query_passes(self):
        s = _scanner()
        body = """
        navigator.permissions.query({name: 'camera'}).then(result => {
            if (result.state === 'granted') enableCamera();
        });
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "permissions_api_bulk_enumeration" not in types


class TestStateTransmitted:
    def test_permission_state_sent_warns(self):
        s = _scanner()
        body = """
        navigator.permissions.query({name: 'camera'}).then(result => {
            fetch('/track', {body: JSON.stringify({cameraState: result.state})});
        });
        """
        s.http.get.return_value = _resp(200, body)
        results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        assert "permissions_api_state_transmitted" in types


class TestNotUsed:
    def test_no_permissions_api_passes(self):
        s = _scanner()
        s.http.get.return_value = _resp(200, "<html>Normal page</html>")
        results = s.scan("http://example.com")
        assert results[0]["type"] == "permissions_api_not_used"

    def test_no_response_passes(self):
        s = _scanner()
        s.http.get.return_value = None
        results = s.scan("http://example.com")
        assert results[0]["status"] == "PASS"
