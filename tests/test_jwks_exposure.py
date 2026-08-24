"""Tests for JWKS Exposure scanner."""
import json
from unittest.mock import MagicMock, patch

import pytest

URL = "https://example.com"


def _make_rsa_key(kid="key1", n_len=342):
    """Create a fake RSA JWK. n_len controls base64url length (342 ≈ 2048 bits)."""
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": "A" * n_len,
        "e": "AQAB",
    }


def _make_ec_key(kid="ec1", crv="P-256"):
    return {"kty": "EC", "kid": kid, "crv": crv, "use": "sig", "x": "abc", "y": "def"}


def _make_oct_key(kid="sym1"):
    return {"kty": "oct", "kid": kid, "k": "dGhlc2VjcmV0", "use": "sig"}


class TestJWKSExposureScanner:
    def _scanner(self):
        from tblue.scanner.jwks_exposure import JWKSExposureScanner
        return JWKSExposureScanner(MagicMock())

    def _resp(self, body="", status=200):
        r = MagicMock()
        r.text = body
        r.status_code = status
        r.headers = {}
        r.url = URL
        return r

    def _jwks_resp(self, keys):
        return self._resp(json.dumps({"keys": keys}), 200)

    def test_no_response_passes(self):
        s = self._scanner()
        with patch.object(s.http, "get", return_value=None):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_no_jwks_endpoint_passes(self):
        s = self._scanner()
        not_found = self._resp("", 404)
        root = self._resp("<html>ok</html>", 200)

        def get_side(url, **kwargs):
            return root if url == URL else not_found

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_good_rsa_key_passes(self):
        """Valid RSA-2048+ key → PASS."""
        s = self._scanner()
        jwks = self._jwks_resp([_make_rsa_key(n_len=342)])
        not_found = self._resp("", 404)
        root = self._resp("<html>ok</html>", 200)

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "jwks" in url:
                return jwks
            return not_found

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        assert any(r["status"] == "PASS" for r in results)

    def test_symmetric_key_fails(self):
        """oct key in JWKS → FAIL."""
        s = self._scanner()
        jwks = self._jwks_resp([_make_oct_key()])
        not_found = self._resp("", 404)
        root = self._resp("<html>ok</html>", 200)

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "jwks" in url:
                return jwks
            return not_found

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        fails = [r for r in results if r["status"] == "FAIL"]
        assert any("symmetric" in r["type"].lower() for r in fails)

    def test_ec_weak_curve_warns(self):
        """EC P-192 curve → WARN."""
        s = self._scanner()
        jwks = self._jwks_resp([_make_ec_key(crv="P-192")])
        not_found = self._resp("", 404)
        root = self._resp("<html>ok</html>", 200)

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "jwks" in url:
                return jwks
            return not_found

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("curve" in r["type"].lower() or "ec" in r["type"].lower() for r in warns)

    def test_kid_collision_warns(self):
        """Two keys with same kid → WARN."""
        s = self._scanner()
        keys = [_make_rsa_key(kid="same", n_len=342), _make_rsa_key(kid="same", n_len=342)]
        jwks = self._jwks_resp(keys)
        not_found = self._resp("", 404)
        root = self._resp("<html>ok</html>", 200)

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "jwks" in url:
                return jwks
            return not_found

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("kid" in r["type"].lower() or "collision" in r["type"].lower() for r in warns)

    def test_excessive_keys_warns(self):
        """More than 10 keys → WARN."""
        s = self._scanner()
        keys = [_make_rsa_key(kid=f"k{i}", n_len=342) for i in range(12)]
        jwks = self._jwks_resp(keys)
        not_found = self._resp("", 404)
        root = self._resp("<html>ok</html>", 200)

        def get_side(url, **kwargs):
            if url == URL:
                return root
            if "jwks" in url:
                return jwks
            return not_found

        with patch.object(s.http, "get", side_effect=get_side):
            results = s.scan(URL)
        warns = [r for r in results if r["status"] == "WARN"]
        assert any("excessive" in r["type"].lower() or "keys" in r["type"].lower() for r in warns)

    def test_result_structure(self):
        s = self._scanner()
        not_found = self._resp("", 404)
        with patch.object(s.http, "get", return_value=not_found):
            results = s.scan(URL)
        for r in results:
            assert "status" in r
            assert r["status"] in ("PASS", "WARN", "FAIL")


class TestHelpers:
    def test_analyze_key_symmetric_fails(self):
        from tblue.scanner.jwks_exposure import _analyze_key
        key = {"kty": "oct", "kid": "s1", "k": "dGhlc2VjcmV0"}
        findings = _analyze_key(key)
        assert any("symmetric" in f["type"].lower() for f in findings)

    def test_analyze_key_good_rsa(self):
        from tblue.scanner.jwks_exposure import _analyze_key
        # n_len=342 represents RSA-2048 modulus → should not trigger weak warning
        key = _make_rsa_key(n_len=342)
        findings = _analyze_key(key)
        weak_findings = [f for f in findings if "weak" in f["type"].lower() or "too-short" in f["type"].lower()]
        assert not weak_findings

    def test_analyze_key_weak_curve(self):
        from tblue.scanner.jwks_exposure import _analyze_key
        key = {"kty": "EC", "crv": "P-192", "kid": "e1", "x": "a", "y": "b"}
        findings = _analyze_key(key)
        assert any("curve" in f["type"].lower() for f in findings)

    def test_check_kid_collisions_found(self):
        from tblue.scanner.jwks_exposure import _check_kid_collisions
        keys = [{"kid": "k1"}, {"kid": "k1"}, {"kid": "k2"}]
        result = _check_kid_collisions(keys)
        assert result is not None
        assert "collision" in result["type"].lower()

    def test_check_kid_collisions_none(self):
        from tblue.scanner.jwks_exposure import _check_kid_collisions
        keys = [{"kid": "k1"}, {"kid": "k2"}]
        result = _check_kid_collisions(keys)
        assert result is None

    def test_check_key_count_normal(self):
        from tblue.scanner.jwks_exposure import _check_key_count
        keys = [{"kid": f"k{i}"} for i in range(3)]
        result = _check_key_count(keys)
        assert result is None

    def test_check_key_count_excessive(self):
        from tblue.scanner.jwks_exposure import _check_key_count
        keys = [{"kid": f"k{i}"} for i in range(11)]
        result = _check_key_count(keys)
        assert result is not None
