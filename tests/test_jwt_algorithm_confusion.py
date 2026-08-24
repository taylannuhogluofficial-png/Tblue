"""Tests for JWT Algorithm Confusion scanner."""
import base64, json as _json
from unittest.mock import MagicMock, patch
URL = "https://example.com"

def _make_jwt(header: dict, payload: dict = None) -> str:
    h = base64.urlsafe_b64encode(_json.dumps(header).encode()).decode().rstrip("=")
    p = base64.urlsafe_b64encode(_json.dumps(payload or {}).encode()).decode().rstrip("=")
    return f"{h}.{p}.fakesig"

class TestJWTAlgorithmConfusionScanner:
    def _scanner(self):
        from tblue.scanner.jwt_algorithm_confusion import JWTAlgorithmConfusionScanner
        return JWTAlgorithmConfusionScanner(MagicMock())
    def _resp(self, body="", status=200, headers=None):
        r = MagicMock(); r.text = body; r.status_code = status; r.headers = headers or {}; return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None): results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_alg_none_fails(self):
        from tblue.scanner.jwt_algorithm_confusion import _check_jwt_algorithm
        findings = _check_jwt_algorithm({"alg": "none"}, URL)
        assert any("none" in f["type"] for f in findings)

    def test_rs256_passes(self):
        from tblue.scanner.jwt_algorithm_confusion import _check_jwt_algorithm
        findings = _check_jwt_algorithm({"alg": "RS256"}, URL)
        fails = [f for f in findings if f["status"] == "FAIL"]
        assert not fails

    def test_hs256_warns(self):
        from tblue.scanner.jwt_algorithm_confusion import _check_jwt_algorithm
        findings = _check_jwt_algorithm({"alg": "HS256"}, URL)
        assert any("symmetric" in f["type"] for f in findings)

    def test_kid_path_traversal_fails(self):
        from tblue.scanner.jwt_algorithm_confusion import _check_jwt_algorithm
        findings = _check_jwt_algorithm({"alg": "RS256", "kid": "../../dev/null"}, URL)
        assert any("kid" in f["type"] for f in findings)

    def test_jwt_in_response_detected(self):
        s = self._scanner()
        jwt = _make_jwt({"alg": "none", "typ": "JWT"}, {"iss": "auth-server", "sub": "user1"})
        with patch.object(s.http, "get", return_value=self._resp(f"token: {jwt}")):
            results = s.scan(URL)
        assert any("none" in r["type"] for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>clean</html>")):
            results = s.scan(URL)
        for r in results: assert r["status"] in ("PASS", "WARN", "FAIL")
