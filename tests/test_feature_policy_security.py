"""Tests for Feature/Permissions Policy Security scanner."""
from unittest.mock import MagicMock, patch
URL = "https://example.com"

class TestFeaturePolicySecurityScanner:
    def _scanner(self):
        from tblue.scanner.feature_policy_security import FeaturePolicySecurityScanner
        return FeaturePolicySecurityScanner(MagicMock())
    def _resp(self, body="OK", status=200, headers=None):
        r = MagicMock(); r.text = body; r.status_code = status; r.headers = headers or {}; return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None): results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_missing_permissions_policy_warns(self):
        from tblue.scanner.feature_policy_security import _check_permissions_policy
        findings = _check_permissions_policy({}, URL)
        assert any("missing" in f["type"] for f in findings)

    def test_strict_policy_passes(self):
        from tblue.scanner.feature_policy_security import _check_permissions_policy
        h = {"permissions-policy": "camera=(), microphone=(), geolocation=()"}
        findings = _check_permissions_policy(h, URL)
        warns = [f for f in findings if f["status"] == "WARN" and "missing" not in f["type"]]
        assert not warns

    def test_wildcard_camera_warns(self):
        from tblue.scanner.feature_policy_security import _check_permissions_policy
        h = {"permissions-policy": "camera=*, microphone=()"}
        findings = _check_permissions_policy(h, URL)
        assert any("camera" in f["type"] for f in findings)

    def test_feature_policy_fallback(self):
        from tblue.scanner.feature_policy_security import _check_permissions_policy
        h = {"feature-policy": "camera 'none'; microphone 'none'"}
        findings = _check_permissions_policy(h, URL)
        warns = [f for f in findings if "missing" in f["type"]]
        assert not warns

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>OK</html>", headers={"permissions-policy": "camera=()"})):
            results = s.scan(URL)
        for r in results: assert r["status"] in ("PASS", "WARN", "FAIL")
