"""Tests for OriginTrialExposureScanner."""
import base64
import json
import struct
import unittest
from unittest.mock import MagicMock, patch
from tblue.scanner.origin_trial_exposure import OriginTrialExposureScanner

URL = "https://example.com"


def _make_token(feature: str, is_third_party: bool = False, expiry: int = 9999999999) -> str:
    """Craft a minimal Origin Trial token with the given feature name."""
    payload = json.dumps({
        "feature": feature,
        "origin": "https://example.com",
        "expiry": expiry,
        "isThirdParty": is_third_party,
    }).encode("utf-8")
    payload_len = struct.pack(">I", len(payload))
    signature = b"\x00" * 64
    version   = b"\x03"
    raw = version + signature + payload_len + payload
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class TestOriginTrialExposure(unittest.TestCase):
    def _make(self):
        s = OriginTrialExposureScanner.__new__(OriginTrialExposureScanner)
        s.http = MagicMock()
        return s

    def _resp(self, body="", status=200, headers=None):
        r = MagicMock()
        r.status_code = status
        r.text = body
        r.headers = headers or {}
        return r

    # ── No tokens ─────────────────────────────────────────────────────────────

    def test_no_tokens_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body="<html><body>hello</body></html>")
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
        self.assertFalse(any(r["status"] == "FAIL" for r in results))

    # ── Header token ─────────────────────────────────────────────────────────

    def test_token_in_header_warns(self):
        token = _make_token("SomeFeature")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={"origin-trial": token})
            results = s.scan(URL)
        warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(len(warns_or_fails) > 0)

    # ── High-risk feature ─────────────────────────────────────────────────────

    def test_direct_sockets_fails(self):
        token = _make_token("DirectSockets")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={"origin-trial": token})
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("DirectSockets" in r["type"] or "high-risk" in r["type"].lower() for r in fails))

    def test_shared_storage_fails(self):
        token = _make_token("SharedStorageAPI")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={"origin-trial": token})
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(any("SharedStorageAPI" in r["type"] or "high-risk" in r["type"].lower() for r in fails))

    # ── Medium-risk feature ───────────────────────────────────────────────────

    def test_private_state_tokens_warns(self):
        token = _make_token("PrivateStateTokens")
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={"origin-trial": token})
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("PrivateStateTokens" in r["type"] or "privacy" in r["type"].lower() for r in warns))

    # ── Third-party token ────────────────────────────────────────────────────

    def test_third_party_token_warns(self):
        token = _make_token("SomeFeature", is_third_party=True)
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={"origin-trial": token})
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        self.assertTrue(any("third-party" in r["type"].lower() or "third party" in r["type"].lower() for r in warns))

    # ── Token in meta tag ─────────────────────────────────────────────────────

    def test_token_in_meta_tag_detected(self):
        token = _make_token("DirectSockets")
        body = (
            "<html><head>"
            f'<meta http-equiv="origin-trial" content="{token}">'
            "</head><body>hello</body></html>"
        )
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(body=body)
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        self.assertTrue(len(fails) > 0)

    # ── Multiple tokens ───────────────────────────────────────────────────────

    def test_multiple_tokens_noted(self):
        t1 = _make_token("FeatureA")
        t2 = _make_token("FeatureB")
        combined = f"{t1},{t2}"
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = self._resp(headers={"origin-trial": combined})
            results = s.scan(URL)
        warns_or_fails = [r for r in results if r["status"] in ("WARN", "FAIL")]
        self.assertTrue(len(warns_or_fails) > 0)

    # ── No response ────────────────────────────────────────────────────────────

    def test_no_response_passes(self):
        s = self._make()
        with patch.object(s, "http") as m:
            m.get.return_value = None
            results = s.scan(URL)
        self.assertTrue(any(r["status"] == "PASS" for r in results))
