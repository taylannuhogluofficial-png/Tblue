"""Tests for PermissionsPolicyDeepScanner."""
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.permissions_policy_deep import PermissionsPolicyDeepScanner

URL = "https://example.com"


def _mock_headers(d):
    m = MagicMock()
    m.items.return_value = list(d.items())
    return m


class TestPermissionsPolicyDeep(unittest.TestCase):
    def _make(self):
        s = PermissionsPolicyDeepScanner.__new__(PermissionsPolicyDeepScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", headers=None):
        r = MagicMock()
        r.status_code = 200
        r.text = body
        r.headers = _mock_headers(headers or {})
        return r

    # ── No Permissions-Policy ─────────────────────────────────────────────────

    def test_missing_header_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp()
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("absent" in r["type"].lower() or "missing" in r["type"].lower() or "permissions" in r["type"].lower() for r in warns))

    # ── Camera wildcard ───────────────────────────────────────────────────────

    def test_camera_wildcard_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={"Permissions-Policy": "camera=*, microphone=()"})
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("camera" in r["type"].lower() for r in fails))

    # ── Payment wildcard ──────────────────────────────────────────────────────

    def test_payment_wildcard_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={"Permissions-Policy": "payment=*, camera=()"})
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("payment" in r["type"].lower() for r in fails))

    # ── Report-only without enforcement ───────────────────────────────────────

    def test_report_only_without_enforcement_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={"Permissions-Policy-Report-Only": "camera=()"})
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("report" in r["type"].lower() or "enforcement" in r["type"].lower() for r in warns))

    # ── Microphone wildcard warns ─────────────────────────────────────────────

    def test_microphone_wildcard_fails(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={"Permissions-Policy": "microphone=*"})
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("microphone" in r["type"].lower() for r in fails))

    # ── HTTP in allowlist ─────────────────────────────────────────────────────

    def test_http_origin_in_allowlist_warns(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(
                headers={"Permissions-Policy": 'camera=("http://partner.com")'}
            )
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(any("http" in r["type"].lower() for r in warns))

    # ── Well-restricted policy passes ────────────────────────────────────────

    def test_well_restricted_passes(self):
        policy = (
            "camera=(), microphone=(), geolocation=(), payment=(), "
            "usb=(), serial=(), bluetooth=(), display-capture=(), "
            "idle-detection=(), interest-cohort=(), browsing-topics=()"
        )
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={"Permissions-Policy": policy})
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── No response ───────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
