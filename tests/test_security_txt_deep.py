"""Tests for security.txt Deep Analysis scanner."""
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta

import pytest

URL = "https://example.com"


class TestSecurityTxtDeepScanner:
    def _scanner(self):
        from tblue.scanner.security_txt_deep import SecurityTxtDeepScanner
        return SecurityTxtDeepScanner(MagicMock())

    def _resp(self, body="", headers=None, status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = headers or {"content-type": "text/plain; charset=utf-8"}
        r.url = URL
        return r

    def _future_date(self, days=365):
        dt = datetime.now(tz=timezone.utc) + timedelta(days=days)
        return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    def _past_date(self, days=30):
        dt = datetime.now(tz=timezone.utc) - timedelta(days=days)
        return dt.strftime("%Y-%m-%dT%H:%M:%S+00:00")

    def test_no_security_txt_warns(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("no security.txt" in r["type"].lower() for r in warns)

    def test_valid_security_txt_passes(self):
        """Fully compliant security.txt → PASS."""
        s = self._scanner()
        body = (
            f"Contact: mailto:security@example.com\n"
            f"Expires: {self._future_date()}\n"
            f"Encryption: https://example.com/pgp-key.asc\n"
            f"Policy: https://example.com/security-policy\n"
            f"Preferred-Languages: en\n"
        )
        resp = self._resp(body)
        with patch.object(s.http, "get", return_value=resp):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert not fails

    def test_expired_security_txt_fails(self):
        """Expired Expires date → FAIL."""
        s = self._scanner()
        body = (
            f"Contact: mailto:security@example.com\n"
            f"Expires: {self._past_date(30)}\n"
        )
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("expired" in r["type"].lower() for r in fails)

    def test_missing_expires_warns(self):
        """No Expires field → WARN."""
        s = self._scanner()
        body = "Contact: mailto:security@example.com\n"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("Expires" in r["type"] for r in warns)

    def test_missing_contact_fails(self):
        """No Contact field → FAIL."""
        s = self._scanner()
        body = f"Expires: {self._future_date()}\n"
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("Contact" in r["type"] for r in fails)

    def test_http_contact_warns(self):
        """Contact with http:// URL → WARN."""
        s = self._scanner()
        body = (
            f"Contact: http://example.com/report\n"
            f"Expires: {self._future_date()}\n"
        )
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("HTTP" in r["type"] or "https" in r["type"].lower() for r in warns)

    def test_missing_encryption_warns(self):
        """No Encryption field → WARN."""
        s = self._scanner()
        body = (
            f"Contact: mailto:security@example.com\n"
            f"Expires: {self._future_date()}\n"
        )
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("Encryption" in r["type"] or "PGP" in r["type"] for r in warns)

    def test_missing_policy_warns(self):
        """No Policy field → WARN."""
        s = self._scanner()
        body = (
            f"Contact: mailto:security@example.com\n"
            f"Expires: {self._future_date()}\n"
            f"Encryption: https://example.com/pgp.asc\n"
        )
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("Policy" in r["type"] for r in warns)

    def test_expiring_soon_warns(self):
        """Expires within 30 days → WARN."""
        s = self._scanner()
        body = (
            f"Contact: mailto:security@example.com\n"
            f"Expires: {self._future_date(days=10)}\n"
        )
        with patch.object(s.http, "get", return_value=self._resp(body)):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("expires" in r["type"].lower() or "expiring" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_parse_iso8601_valid(self):
        from tblue.scanner.security_txt_deep import _parse_iso8601
        dt = _parse_iso8601("2027-01-01T00:00:00+00:00")
        assert dt is not None
        assert dt.year == 2027

    def test_parse_iso8601_z_suffix(self):
        from tblue.scanner.security_txt_deep import _parse_iso8601
        dt = _parse_iso8601("2027-06-15T12:30:00Z")
        assert dt is not None
        assert dt.month == 6

    def test_parse_iso8601_invalid(self):
        from tblue.scanner.security_txt_deep import _parse_iso8601
        assert _parse_iso8601("not-a-date") is None
        assert _parse_iso8601("January 1, 2027") is None

    def test_bcp47_valid_codes(self):
        from tblue.scanner.security_txt_deep import _BCP47_RE
        assert _BCP47_RE.match("en")
        assert _BCP47_RE.match("en-US")
        assert _BCP47_RE.match("zh-Hans")
        assert _BCP47_RE.match("fr")

    def test_bcp47_invalid_codes(self):
        from tblue.scanner.security_txt_deep import _BCP47_RE
        assert not _BCP47_RE.match("english")
        assert not _BCP47_RE.match("EN_US")
