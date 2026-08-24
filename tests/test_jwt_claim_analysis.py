"""Tests for JWT Claim Analysis scanner."""
import base64
import json
from unittest.mock import MagicMock, patch

URL = "https://example.com"


def _make_jwt(header: dict, payload: dict) -> str:
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64(header)}.{b64(payload)}.fakesig"


class TestJWTClaimAnalysisScanner:
    def _scanner(self):
        from tblue.scanner.jwt_claim_analysis import JWTClaimAnalysisScanner
        return JWTClaimAnalysisScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        return r

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_jwt_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>no tokens</html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_alg_none_fails(self):
        token = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "1", "exp": 9999999999})
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(f"token={token}")):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("none" in r["type"] for r in fails)

    def test_weak_alg_warns(self):
        token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 9999999999})
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(f"token={token}")):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] in ("WARN", "FAIL")]
        assert any("hs256" in r["type"] or "weak" in r["type"] for r in warns)

    def test_missing_exp_warns(self):
        token = _make_jwt({"alg": "RS256", "typ": "JWT"}, {"sub": "user1"})
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(f"var t = '{token}'")):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("exp" in r["type"] for r in warns)

    def test_sensitive_claim_warns(self):
        token = _make_jwt({"alg": "RS256", "typ": "JWT"}, {"sub": "1", "exp": 9999, "password": "secret123"})
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp(f"tok={token}")):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("sensitive" in r["type"] for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html></html>")):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_extract_jwts(self):
        from tblue.scanner.jwt_claim_analysis import _extract_jwts
        token = _make_jwt({"alg": "HS256"}, {"sub": "1"})
        assert token in _extract_jwts(f"Bearer {token}")

    def test_extract_jwts_empty(self):
        from tblue.scanner.jwt_claim_analysis import _extract_jwts
        assert _extract_jwts("no tokens here") == []

    def test_decode_jwt_part(self):
        from tblue.scanner.jwt_claim_analysis import _decode_jwt_part
        data = {"alg": "none"}
        part = base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()
        assert _decode_jwt_part(part) == data

    def test_check_jwt_no_exp(self):
        from tblue.scanner.jwt_claim_analysis import _check_jwt
        token = _make_jwt({"alg": "RS256"}, {"sub": "1"})
        findings = _check_jwt(token, URL)
        assert any("exp" in f["type"] for f in findings)

    def test_check_jwt_good_token_no_findings(self):
        from tblue.scanner.jwt_claim_analysis import _check_jwt
        token = _make_jwt({"alg": "RS256"}, {"sub": "1", "exp": 9999999999, "iat": 1000000000})
        findings = _check_jwt(token, URL)
        assert findings == []
