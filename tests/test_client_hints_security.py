"""Tests for Client Hints Security scanner."""
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"
URL_HTTP = "http://example.com"


class TestClientHintsSecurityScanner:
    def _scanner(self):
        from tblue.scanner.client_hints_security import ClientHintsSecurityScanner
        return ClientHintsSecurityScanner(MagicMock())

    def _resp(self, headers=None, status=200):
        r = MagicMock()
        r.text = "<html>ok</html>"
        r.status_code = status
        r.headers = headers or {}
        r.url = URL
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_accept_ch_passes(self):
        """No Accept-CH at all → PASS."""
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_high_entropy_hints_warns(self):
        """Accept-CH with Device-Memory and DPR → WARN."""
        s = self._scanner()
        headers = {"accept-ch": "Device-Memory, DPR, Sec-CH-UA-Full-Version-List"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("entropy" in r["type"].lower() or "fingerprint" in r["type"].lower()
                   or "high-entropy" in r["type"].lower() for r in warns)

    def test_low_entropy_hint_passes(self):
        """Accept-CH with Sec-CH-UA only (low entropy) → no high-entropy warning."""
        s = self._scanner()
        headers = {"accept-ch": "Sec-CH-UA"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        he_warns = [r for r in results if "entropy" in r.get("type", "").lower()]
        assert not he_warns

    def test_sec_hints_on_http_warns(self):
        """Sec- hints requested over HTTP → WARN (they are silently dropped)."""
        s = self._scanner()
        headers = {"accept-ch": "Sec-CH-UA-Platform, Sec-CH-UA-Model"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL_HTTP)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("http" in r["type"].lower() or "sec" in r["type"].lower() for r in warns)

    def test_accept_ch_lifetime_warns(self):
        """Accept-CH-Lifetime (deprecated) → WARN."""
        s = self._scanner()
        headers = {"accept-ch-lifetime": "86400"}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("lifetime" in r["type"].lower() or "deprecated" in r["type"].lower() for r in warns)

    def test_delegate_ch_wildcard_warns(self):
        """Permissions-Policy delegate-ch with * → WARN."""
        s = self._scanner()
        pp = "delegate-ch=(Sec-CH-UA-Full-Version-List *)"
        headers = {"permissions-policy": pp}
        with patch.object(s.http, "get", return_value=self._resp(headers)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("wildcard" in r["type"].lower() or "delegate" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp()):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_parse_accept_ch(self):
        from tblue.scanner.client_hints_security import _parse_accept_ch
        result = _parse_accept_ch("Device-Memory, DPR, Sec-CH-UA")
        assert "device-memory" in result
        assert "dpr" in result
        assert "sec-ch-ua" in result

    def test_check_accept_ch_high_entropy(self):
        from tblue.scanner.client_hints_security import _check_accept_ch
        findings = _check_accept_ch(
            {"accept-ch": "Device-Memory, Sec-CH-UA-Full-Version-List"}, True)
        assert any("entropy" in f["type"].lower() for f in findings)

    def test_check_accept_ch_low_entropy(self):
        from tblue.scanner.client_hints_security import _check_accept_ch
        findings = _check_accept_ch({"accept-ch": "Sec-CH-UA"}, True)
        he_finds = [f for f in findings if "entropy" in f["type"].lower()]
        assert not he_finds

    def test_check_accept_ch_sec_on_http(self):
        from tblue.scanner.client_hints_security import _check_accept_ch
        findings = _check_accept_ch({"accept-ch": "Sec-CH-UA-Model"}, False)
        assert any("http" in f["type"].lower() or "sec" in f["type"].lower() for f in findings)

    def test_check_accept_ch_lifetime(self):
        from tblue.scanner.client_hints_security import _check_accept_ch_lifetime
        result = _check_accept_ch_lifetime({"accept-ch-lifetime": "3600"})
        assert result is not None
        assert "deprecated" in result["type"].lower()

    def test_check_accept_ch_lifetime_absent(self):
        from tblue.scanner.client_hints_security import _check_accept_ch_lifetime
        result = _check_accept_ch_lifetime({})
        assert result is None

    def test_check_delegate_ch_wildcard(self):
        from tblue.scanner.client_hints_security import _check_delegate_ch
        headers = {"permissions-policy": "delegate-ch=(Sec-CH-UA-Platform-Version *)"}
        findings = _check_delegate_ch(headers)
        assert findings
        assert any("wildcard" in f["type"].lower() for f in findings)

    def test_check_delegate_ch_specific_origin(self):
        from tblue.scanner.client_hints_security import _check_delegate_ch
        headers = {"permissions-policy": 'delegate-ch=(Sec-CH-UA "https://cdn.example.com")'}
        findings = _check_delegate_ch(headers)
        wildcard_finds = [f for f in findings if "wildcard" in f["type"].lower()]
        assert not wildcard_finds
