"""Tests for OAuth Device Authorization Grant scanner."""
import unittest
from unittest.mock import MagicMock, patch
import json
from tblue.scanner.oauth_device_flow import OAuthDeviceFlowScanner


def _resp(body="", status=200):
    r = MagicMock()
    r.status_code = status
    r.text = body
    r.headers = {}
    return r


class TestOAuthDeviceFlow(unittest.TestCase):

    def _scanner(self):
        s = OAuthDeviceFlowScanner.__new__(OAuthDeviceFlowScanner)
        s.http = MagicMock()
        s.results = []
        s._result = lambda url, ftype, sev, detail="": {
            "url": url, "type": ftype, "severity": sev, "detail": detail
        }
        return s

    def _not_found(self):
        return _resp("", 404)

    def test_no_device_flow(self):
        s = self._scanner()
        s.http.get.return_value = self._not_found()
        results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("oauth_device_flow_not_detected", types)

    def test_long_lived_device_code_flagged(self):
        s = self._scanner()
        device_resp = json.dumps({
            "device_code": "abc123",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://example.com/activate",
            "expires_in": 3600,
            "interval": 5,
        })

        def get_side(url, **kw):
            if "device" in url.lower() and url != "https://example.com":
                return _resp(device_resp, 200)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("oauth_device_long_lived_code", types)

    def test_low_entropy_user_code_flagged(self):
        s = self._scanner()
        device_resp = json.dumps({
            "device_code": "abc",
            "user_code": "1234",
            "verification_uri": "https://example.com/activate",
            "expires_in": 300,
            "interval": 5,
        })

        def get_side(url, **kw):
            if "device" in url.lower() and url != "https://example.com":
                return _resp(device_resp, 200)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("oauth_device_low_entropy_user_code", types)

    def test_fast_polling_flagged(self):
        s = self._scanner()
        device_resp = json.dumps({
            "device_code": "abc123",
            "user_code": "LONG-RANDOM-CODE",
            "verification_uri": "https://example.com/activate",
            "expires_in": 300,
            "interval": 2,
        })

        def get_side(url, **kw):
            if "device" in url.lower() and url != "https://example.com":
                return _resp(device_resp, 200)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("oauth_device_fast_polling", types)

    def test_device_endpoint_in_oidc_discovery(self):
        s = self._scanner()
        discovery = json.dumps({
            "issuer": "https://example.com",
            "device_authorization_endpoint": "https://example.com/device",
        })

        def get_side(url, **kw):
            if ".well-known/openid-configuration" in url:
                return _resp(discovery, 200)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("https://example.com")
        types = [r["type"] for r in results]
        self.assertIn("oauth_device_endpoint_advertised", types)

    def test_no_tls_on_device_endpoint_http(self):
        s = self._scanner()
        device_resp = json.dumps({
            "device_code": "abc",
            "user_code": "ABCD-EFGH",
            "verification_uri": "http://example.com/activate",
            "expires_in": 300,
            "interval": 5,
        })

        def get_side(url, **kw):
            if "device" in url.lower() and url != "http://example.com":
                return _resp(device_resp, 200)
            return self._not_found()

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan("http://example.com")
        types = [r["type"] for r in results]
        self.assertIn("oauth_device_no_tls", types)


if __name__ == "__main__":
    unittest.main()
