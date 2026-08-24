"""Tests for JWTTokenExposureScanner."""
import pytest
from unittest.mock import MagicMock, patch
from tblue.scanner.jwt_token_exposure import (
    JWTTokenExposureScanner, _check_jwt_in_body, _check_jwt_in_url,
    _decode_jwt_header,
)

URL = "https://example.com"

_NONE_ALG_JWT = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
_HS256_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"


class TestJWTTokenExposure:
    def _scanner(self):
        return JWTTokenExposureScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        return r

    def test_decode_jwt_header_none(self):
        header = _decode_jwt_header(_NONE_ALG_JWT)
        assert header.get("alg") == "none"

    def test_decode_jwt_header_hs256(self):
        header = _decode_jwt_header(_HS256_JWT)
        assert header.get("alg") == "HS256"

    def test_none_alg_jwt_in_body_fails(self):
        findings = _check_jwt_in_body(f"var token = '{_NONE_ALG_JWT}';", URL)
        assert any("none" in f["type"] for f in findings)

    def test_hs256_jwt_in_body_warns(self):
        findings = _check_jwt_in_body(f"var token = '{_HS256_JWT}';", URL)
        warns = [f for f in findings if "hmac" in f["type"]]
        assert len(warns) > 0

    def test_jwt_in_url_fails(self):
        url_with_jwt = f"https://example.com/callback?token={_HS256_JWT}"
        findings = _check_jwt_in_url(url_with_jwt)
        assert any("url" in f["type"] for f in findings)

    def test_jwt_localstorage_warns(self):
        body = "localStorage.setItem('auth_token', response.token);"
        findings = _check_jwt_in_body(body, URL)
        warns = [f for f in findings if "localstorage" in f["type"]]
        assert len(warns) > 0

    def test_no_jwt_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("<html>Normal page</html>")):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_result_structure(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=self._resp("ok")):
            results = s.scan(URL)
        for r in results:
            assert r["status"] in ("PASS", "WARN", "FAIL", "INFO")
